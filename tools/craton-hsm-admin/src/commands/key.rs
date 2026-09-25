// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use super::Ctx;
use crate::admin_core::{open_core, Role, SLOT};
use crate::error::{CliError, CliResult};
use crate::output;
use craton_hsm::audit::log::AuditOperation;
use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::types::{CK_ATTRIBUTE_TYPE, CK_OBJECT_HANDLE, CK_ULONG};
use craton_hsm::store::attributes::ObjectContext;
use craton_hsm::store::object::StoredObject;
use zeroize::Zeroizing;

/// Maximum size of a key file accepted by `key import` (H5-16).
const MAX_KEY_FILE_BYTES: u64 = 16 * 1024;

/// Key types accepted by `key import`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ImportKeyType {
    /// Raw AES key: exactly 16, 24 or 32 bytes.
    Aes,
}

fn ck_ulong_bytes(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

/// Key size in bits for display (overflow-safe, H5-17).
fn size_bits(obj: &StoredObject) -> Option<CK_ULONG> {
    obj.modulus_bits
        .or_else(|| obj.value_len.and_then(|v| v.checked_mul(8)))
}

/// List keys visible to the authenticated role. An SO session does not see
/// private (user) objects (H5-14).
pub fn list(ctx: &Ctx, role: Role) -> CliResult {
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("key list")?;
    let session = core.login(role)?;

    let store = core.hsm().object_store();
    // Private objects are visible to the User role only (H5-14).
    let handles = store.find_objects_for_slot(&[], role == Role::User, Some(SLOT));

    let mut rows = Vec::new();
    for handle in &handles {
        if let Ok(obj_lock) = store.get_object_in_slot(*handle, SLOT) {
            let obj = obj_lock.read();
            rows.push((
                obj.handle,
                output::object_class_name(u64::from(obj.class)),
                obj.key_type.map(|kt| output::key_type_name(u64::from(kt))),
                output::display_label(&obj.label),
                size_bits(&obj),
                obj.sensitive,
                obj.extractable,
            ));
        }
    }
    drop(session);

    if ctx.json {
        let objects: Vec<_> = rows
            .iter()
            .map(|(h, class, kt, label, size, sens, ext)| {
                serde_json::json!({
                    "handle": h,
                    "class": class,
                    "key_type": kt,
                    "label": label,
                    "size_bits": size,
                    "sensitive": sens,
                    "extractable": ext,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&objects)?);
    } else {
        let mut table = output::ObjectTable::new(vec![
            "Handle",
            "Class",
            "Type",
            "Label",
            "Size",
            "Sensitive",
            "Extractable",
        ]);
        for (h, class, kt, label, size, sens, ext) in &rows {
            table.add_row(vec![
                h.to_string(),
                class.to_string(),
                kt.unwrap_or("-").to_string(),
                label.clone(),
                size.map_or_else(|| "-".to_string(), |s| s.to_string()),
                sens.to_string(),
                ext.to_string(),
            ]);
        }
        println!("Key Objects");
        println!("===========");
        print!("{table}");
        println!("\nTotal: {} object(s)", rows.len());
    }
    Ok(())
}

/// Validate raw AES key material (H5-13).
pub fn validate_aes_key(bytes: &[u8]) -> CliResult {
    match bytes.len() {
        16 | 24 | 32 => Ok(()),
        n => Err(CliError::Usage(format!(
            "AES key file must contain exactly 16, 24 or 32 raw bytes (found {n}). \
             PEM/DER and RSA/EC keys are not supported by 'key import'; use \
             C_CreateObject/C_UnwrapKey through PKCS#11."
        ))),
    }
}

/// Import a raw AES key as a private, sensitive, non-extractable token
/// object. Requires a User login (objects created under SO would otherwise
/// be private objects owned by the wrong role).
pub fn import(ctx: &Ctx, file: &std::path::Path, label: &str, _kt: ImportKeyType) -> CliResult {
    let label_bytes = super::token::validate_label(label)?;
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("key import")?;
    core.require_audit_intact()?;

    let key_data = crate::fsutil::read_bounded(file, MAX_KEY_FILE_BYTES, "key file")?;
    validate_aes_key(&key_data)?;

    let session = core.login(Role::User)?;

    let label_trimmed = &label_bytes[..label.len()];
    let value_len = key_data.len() as CK_ULONG;
    let template: Zeroizing<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>> = Zeroizing::new(vec![
        (CKA_CLASS, ck_ulong_bytes(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ck_ulong_bytes(CKK_AES)),
        (CKA_LABEL, label_trimmed.to_vec()),
        (CKA_TOKEN, vec![1u8]),
        (CKA_PRIVATE, vec![1u8]),
        (CKA_SENSITIVE, vec![1u8]),
        (CKA_EXTRACTABLE, vec![0u8]),
        (CKA_VALUE_LEN, ck_ulong_bytes(value_len)),
        (CKA_VALUE, key_data.to_vec()),
    ]);
    // C_CreateObject semantics through the core (attribute policy, slot
    // and session binding, persisted before it becomes visible).
    let res = core.hsm().object_store().create_object_in(
        &template,
        &ObjectContext::new(SLOT, session.session(), false),
    );
    drop(template);
    drop(key_data);

    core.record(
        session.session(),
        AuditOperation::CreateObject,
        res.as_ref().map(|_| ()),
        &format!("key-import:{}", res.as_ref().map_or(0, |h| *h)),
    )?;
    let handle = res.map_err(|e| CliError::General(format!("Failed to import key: {e}")))?;
    drop(session);

    println!("Key imported successfully.");
    println!("  Handle: {handle}");
    println!("  Label:  {label}");
    println!("  Type:   AES-{}", value_len * 8);
    Ok(())
}

/// Convert a user-supplied handle without truncation (H5-14).
pub fn parse_handle(handle: u64) -> CliResult<CK_OBJECT_HANDLE> {
    let h = CK_OBJECT_HANDLE::try_from(handle).map_err(|_| {
        CliError::Usage(format!(
            "Object handle {handle} is out of range for this platform."
        ))
    })?;
    if h == 0 {
        return Err(CliError::Usage(
            "Object handle 0 is CK_INVALID_HANDLE.".into(),
        ));
    }
    Ok(h)
}

/// Delete a key by handle after authentication and typed confirmation.
pub fn delete(ctx: &Ctx, handle: u64, role: Role) -> CliResult {
    let handle = parse_handle(handle)?;
    let cfg = ctx.load_config()?;
    let core = open_core(&cfg)?;
    core.require_persistent("key delete")?;
    core.require_audit_intact()?;
    let session = core.login(role)?;

    let (label, class, private) = {
        let obj_lock = core
            .hsm()
            .object_store()
            .get_object_in_slot(handle, SLOT)
            .map_err(|_| CliError::Usage(format!("Object handle {handle} not found.")))?;
        let obj = obj_lock.read();
        (
            output::display_label(&obj.label),
            output::object_class_name(u64::from(obj.class)),
            obj.private,
        )
    };
    if private && role != Role::User {
        return Err(CliError::Refused(
            "Private objects can only be deleted by the User role (PKCS#11).".into(),
        ));
    }

    crate::prompt::confirm_typed(
        &format!("Delete {class} object {handle} (label '{label}')? This cannot be undone."),
        "delete",
        ctx.yes,
    )?;

    let res = core.hsm().object_store().destroy_object_in(handle, SLOT);
    core.record(
        session.session(),
        AuditOperation::DestroyObject,
        res.as_ref().map(|_| ()),
        &format!("key-delete:{handle}"),
    )?;
    res.map_err(|e| CliError::General(format!("Failed to destroy object: {e}")))?;
    drop(session);

    println!("Object {handle} deleted.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_key_lengths() {
        assert!(validate_aes_key(&[0u8; 16]).is_ok());
        assert!(validate_aes_key(&[0u8; 24]).is_ok());
        assert!(validate_aes_key(&[0u8; 32]).is_ok());
        assert!(validate_aes_key(&[0u8; 15]).is_err());
        assert!(validate_aes_key(&[0u8; 33]).is_err());
        assert!(validate_aes_key(b"-----BEGIN PRIVATE KEY-----").is_err());
    }

    #[test]
    fn handle_conversion_is_checked() {
        assert!(parse_handle(0).is_err());
        assert_eq!(parse_handle(5).unwrap(), 5);
        if std::mem::size_of::<CK_OBJECT_HANDLE>() < 8 {
            assert!(parse_handle(u64::from(u32::MAX) + 1).is_err());
        } else {
            assert!(parse_handle(u64::MAX).is_ok());
        }
    }

    #[test]
    fn size_bits_does_not_overflow() {
        let mut obj = StoredObject::new(1, CKO_SECRET_KEY);
        obj.value_len = Some(CK_ULONG::MAX);
        assert_eq!(size_bits(&obj), None);
        obj.value_len = Some(32);
        assert_eq!(size_bits(&obj), Some(256));
    }
}
