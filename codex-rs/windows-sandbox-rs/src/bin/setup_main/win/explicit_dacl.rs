use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACE_HEADER;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
use windows_sys::Win32::Security::AclSizeInformation;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetAce;
use windows_sys::Win32::Security::GetAclInformation;

use super::no_reparse_dir::open_existing_no_reparse_for_read_control;

const INHERITED_ACE: u8 = 0x10;

/// Returns whether `dir` already carries exactly the explicit ACEs of `expected`.
///
/// The directory is opened read-only without following a reparse point in any
/// path component, so the verdict is about the real directory at `dir` and never
/// about a junction, symlink, or mount point target. Inherited ACEs are ignored
/// because a DACL written with `DACL_SECURITY_INFORMATION` only controls the
/// explicit entries. Nothing is modified.
///
/// # Safety
/// `expected` must point to a valid ACL.
pub(super) unsafe fn explicit_dacl_matches(dir: &Path, expected: *const ACL) -> Result<bool> {
    let directory = open_existing_no_reparse_for_read_control(dir)?;
    let mut current_dacl: *mut ACL = std::ptr::null_mut();
    let mut security_descriptor: *mut c_void = std::ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            directory.as_raw_handle() as _,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut current_dacl,
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if code != 0 {
        bail!("GetSecurityInfo sandbox dir failed: {code}");
    }
    let current = unsafe { explicit_aces(current_dacl) };
    unsafe {
        LocalFree(security_descriptor as HLOCAL);
    }
    let mut current = current?;
    let mut expected = unsafe { explicit_aces(expected) }?;
    // ACE order is not significant for this comparison: every entry in the lock is
    // an explicit allow or deny for a distinct trustee.
    current.sort();
    expected.sort();
    Ok(!expected.is_empty() && current == expected)
}

/// Copies the raw bytes of every non-inherited ACE in `acl`.
///
/// # Safety
/// `acl` must be null or point to a valid ACL.
unsafe fn explicit_aces(acl: *const ACL) -> Result<Vec<Vec<u8>>> {
    ensure!(!acl.is_null(), "sandbox dir has a NULL DACL");
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        bail!("GetAclInformation sandbox dir failed: {}", unsafe {
            GetLastError()
        });
    }
    let mut aces = Vec::new();
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 {
            bail!("GetAce sandbox dir failed: {}", unsafe { GetLastError() });
        }
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        if header.AceFlags & INHERITED_ACE != 0 {
            continue;
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(ace as *const u8, usize::from(header.AceSize)) };
        aces.push(bytes.to_vec());
    }
    Ok(aces)
}
