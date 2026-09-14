use super::DELETE;
use super::FILE_GENERIC_EXECUTE;
use super::FILE_GENERIC_READ;
use super::FILE_GENERIC_WRITE;
use super::GRANT_ACCESS;
use super::lock_sandbox_dir;
use super::resolve_sid;
use super::string_from_sid_bytes;
use super::to_wide;
use pretty_assertions::assert_eq;
use std::ffi::c_void;
use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::path::Prefix;
use std::process::Command;
use std::process::Stdio;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SDDL_REVISION_1;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;

const SANDBOX_BIN_GROUP_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const SANDBOX_BIN_REAL_USER_MASK: u32 =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
/// Set to a writable directory on another drive to repeat the per-drive tests there.
const EXTRA_DRIVE_TEST_ROOT_ENV: &str = "CODEX_NO_REPARSE_TEST_ROOT";

fn real_user() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string())
}

/// Stand-in for the sandbox users group; any existing SID other than the real
/// user keeps the lock's trustees distinct.
fn sandbox_group_sid() -> Vec<u8> {
    resolve_sid("Users").expect("resolve Users SID")
}

fn lock_sandbox_bin(dir: &Path, group_mask: u32) -> anyhow::Result<()> {
    lock_sandbox_dir(
        dir,
        &real_user(),
        &sandbox_group_sid(),
        GRANT_ACCESS,
        group_mask,
        SANDBOX_BIN_REAL_USER_MASK,
    )
}

/// Temporary directories on the default temp volume plus, when configured, on
/// the extra drive root.
fn drive_letter_temp_dirs() -> Vec<tempfile::TempDir> {
    let mut dirs = vec![tempfile::tempdir().expect("tempdir")];
    if let Some(root) = std::env::var_os(EXTRA_DRIVE_TEST_ROOT_ENV) {
        let root = PathBuf::from(root);
        fs::create_dir_all(&root).expect("create extra drive test root");
        dirs.push(tempfile::tempdir_in(root).expect("extra drive tempdir"));
    }
    dirs
}

/// Owner and DACL of `path` as SDDL. With `follow == false` the reparse point
/// object itself is read instead of its target.
fn security_of(path: &Path, follow: bool) -> String {
    let wide = to_wide(path.as_os_str());
    let flags = if follow {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    };
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            0,
        );
        assert_ne!(
            handle,
            INVALID_HANDLE_VALUE,
            "open {} for READ_CONTROL: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut security_descriptor: *mut c_void = std::ptr::null_mut();
        let code = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut security_descriptor,
        );
        CloseHandle(handle);
        assert_eq!(code, 0, "read security of {}", path.display());
        let mut sddl: *mut u16 = std::ptr::null_mut();
        let mut len = 0;
        assert_ne!(
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                security_descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut sddl,
                &mut len,
            ),
            0
        );
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(sddl, len as usize))
            .trim_end_matches('\0')
            .to_string();
        LocalFree(sddl as HLOCAL);
        LocalFree(security_descriptor as HLOCAL);
        text
    }
}

fn snapshot(objects: &[(&Path, bool)]) -> Vec<String> {
    objects
        .iter()
        .map(|(path, follow)| security_of(path, *follow))
        .collect()
}

fn assert_rejected(result: anyhow::Result<()>, reason: &str) {
    let error = result.expect_err("the sandbox directory lock must be rejected");
    assert!(
        format!("{error:#}").contains(reason),
        "expected `{reason}`, got: {error:#}"
    );
}

/// Replaces the DACL of `path` with the protected DACL in `sddl`.
fn set_protected_dacl(path: &Path, sddl: &str) {
    let sddl_w = to_wide(sddl);
    let mut security_descriptor: *mut c_void = std::ptr::null_mut();
    unsafe {
        assert_ne!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut security_descriptor,
                std::ptr::null_mut(),
            ),
            0,
            "parse SDDL {sddl}"
        );
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        assert_ne!(
            GetSecurityDescriptorDacl(security_descriptor, &mut present, &mut dacl, &mut defaulted),
            0
        );
        let path_w = to_wide(path.as_os_str());
        let code = SetNamedSecurityInfoW(
            path_w.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        );
        LocalFree(security_descriptor as HLOCAL);
        assert_eq!(code, 0, "set protected DACL on {}", path.display());
    }
}

fn write_dac_open_error(path: &Path) -> Option<i32> {
    fs::OpenOptions::new()
        .access_mode(WRITE_DAC)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .err()
        .and_then(|err| err.raw_os_error())
}

fn create_directory_junction(target: &Path, alias: &Path) {
    let output = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(alias)
        .arg(target)
        .output()
        .expect("run mklink /J");
    assert!(
        output.status.success(),
        "mklink /J failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Directory symlinks need SeCreateSymbolicLinkPrivilege or Developer Mode.
fn try_create_directory_symlink(target: &Path, alias: &Path) -> bool {
    Command::new("cmd")
        .args(["/C", "mklink", "/D"])
        .arg(alias)
        .arg(target)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn drive_letter_and_relative(path: &Path) -> (char, PathBuf) {
    let mut components = path.components();
    let letter = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => char::from(letter),
            other => panic!("temporary directory is not on a drive letter: {other:?}"),
        },
        other => panic!("temporary directory has no drive prefix: {other:?}"),
    };
    assert!(matches!(components.next(), Some(Component::RootDir)));
    (letter, components.collect())
}

fn unused_drive_letter() -> Option<char> {
    ('M'..='Z')
        .rev()
        .find(|letter| !Path::new(&format!("{letter}:\\")).exists())
}

/// Takes away the real user's ability to change DACLs below `home`, the way a
/// directory locked by elevated setup looks to the later non-elevated refresh.
///
/// OWNER RIGHTS replaces the owner's implicit READ_CONTROL and WRITE_DAC, and
/// the protected DACL drops inherited full control.
fn remove_write_dac_below(home: &Path) {
    let user_sid = string_from_sid_bytes(&resolve_sid(&real_user()).expect("resolve user SID"))
        .expect("user SID string");
    set_protected_dacl(
        home,
        &format!("D:P(A;OICI;0x1301bf;;;OW)(A;OICI;0x1301bf;;;{user_sid})(A;OICI;FA;;;SY)"),
    );
}

/// `<root>/<name>/.sandbox-bin` locked with `group_mask`, then without WRITE_DAC
/// for the real user.
fn locked_without_write_dac(root: &Path, name: &str, group_mask: u32) -> PathBuf {
    let home = root.join(name);
    fs::create_dir(&home).expect("create home");
    let sandbox_bin = home.join(".sandbox-bin");
    lock_sandbox_bin(&sandbox_bin, group_mask).expect("initial lock");
    remove_write_dac_below(&home);
    assert_eq!(
        write_dac_open_error(&sandbox_bin),
        Some(ERROR_ACCESS_DENIED as i32),
        "precondition: the real user must not be able to rewrite the DACL"
    );
    sandbox_bin
}

/// `<root>/<name>/.sandbox-bin` as a real directory the real user controls.
fn writable_real_directory(root: &Path, name: &str) -> PathBuf {
    let sandbox_bin = root.join(name).join(".sandbox-bin");
    fs::create_dir_all(&sandbox_bin).expect("create real sandbox bin");
    assert_eq!(
        write_dac_open_error(&sandbox_bin),
        None,
        "precondition: the real user can rewrite the DACL"
    );
    sandbox_bin
}

// ---- allowed ----

#[test]
fn locks_real_directory_through_verified_handle_on_every_test_drive() {
    for temp in drive_letter_temp_dirs() {
        let sandbox_bin = writable_real_directory(temp.path(), "home");

        lock_sandbox_bin(&sandbox_bin, SANDBOX_BIN_GROUP_MASK).expect("lock real directory");

        let group_sid = string_from_sid_bytes(&sandbox_group_sid()).expect("group SID string");
        let sddl = security_of(&sandbox_bin, true);
        assert!(
            sddl.contains("(A;OICI;0x1200a9;;;BU)")
                || sddl.contains(&format!("(A;OICI;0x1200a9;;;{group_sid})")),
            "sandbox group read ACE missing: {sddl}"
        );
    }
}

#[test]
fn creates_and_locks_missing_final_directory_on_every_test_drive() {
    for temp in drive_letter_temp_dirs() {
        let home = temp.path().join("home");
        fs::create_dir(&home).expect("create home");
        let sandbox_bin = home.join(".sandbox-bin");

        lock_sandbox_bin(&sandbox_bin, SANDBOX_BIN_GROUP_MASK).expect("create and lock");

        assert!(sandbox_bin.is_dir());
    }
}

// Regression: after elevated setup locked `.sandbox-bin`, every non-elevated
// refresh failed with ERROR_ACCESS_DENIED because the real user cannot rewrite a
// DACL it does not control, even an identical one.
#[test]
fn accepts_existing_identical_lock_without_write_dac_on_every_test_drive() {
    for temp in drive_letter_temp_dirs() {
        let sandbox_bin = locked_without_write_dac(temp.path(), "home", SANDBOX_BIN_GROUP_MASK);
        let before = security_of(&sandbox_bin, true);

        lock_sandbox_bin(&sandbox_bin, SANDBOX_BIN_GROUP_MASK)
            .expect("refresh must accept an existing identical lock");

        assert_eq!(security_of(&sandbox_bin, true), before);
    }
}

// ---- rejected: DACL state ----

#[test]
fn rejects_existing_lock_with_different_aces_without_write_dac() {
    let temp = tempfile::tempdir().expect("tempdir");
    // The existing DACL lets the sandbox group write; the required lock does not.
    let sandbox_bin = locked_without_write_dac(
        temp.path(),
        "home",
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
    );
    let before = security_of(&sandbox_bin, true);

    assert_rejected(
        lock_sandbox_bin(&sandbox_bin, SANDBOX_BIN_GROUP_MASK),
        "does not match",
    );

    assert_eq!(security_of(&sandbox_bin, true), before);
}

#[test]
fn rejects_unlocked_directory_without_write_dac() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    let sandbox_bin = home.join(".sandbox-bin");
    fs::create_dir_all(&sandbox_bin).expect("create unlocked sandbox bin");
    remove_write_dac_below(&home);
    let before = security_of(&sandbox_bin, true);

    assert_rejected(
        lock_sandbox_bin(&sandbox_bin, SANDBOX_BIN_GROUP_MASK),
        "does not match",
    );

    assert_eq!(security_of(&sandbox_bin, true), before);
}

#[test]
fn rejects_missing_sandbox_home_without_creating_it() {
    for temp in drive_letter_temp_dirs() {
        let home = temp.path().join("missing-home");

        assert_rejected(
            lock_sandbox_bin(&home.join(".sandbox-bin"), SANDBOX_BIN_GROUP_MASK),
            "open sandbox ACL directory",
        );

        assert!(!home.exists(), "the sandbox home must not be created");
    }
}

// ---- rejected: reparse points (probe matrix S3-S6) ----

#[test]
fn rejects_final_junction_to_locked_directory_on_every_test_drive() {
    for temp in drive_letter_temp_dirs() {
        let target = locked_without_write_dac(temp.path(), "real-home", SANDBOX_BIN_GROUP_MASK);
        let other_home = temp.path().join("other-home");
        fs::create_dir(&other_home).expect("create other home");
        let alias = other_home.join(".sandbox-bin");
        create_directory_junction(&target, &alias);
        let objects = [(target.as_path(), true), (alias.as_path(), false)];
        let before = snapshot(&objects);

        let result = lock_sandbox_bin(&alias, SANDBOX_BIN_GROUP_MASK);
        let after = snapshot(&objects);
        fs::remove_dir(&alias).expect("remove junction");

        assert_rejected(result, "reparse point");
        assert_eq!(after, before);
    }
}

#[test]
fn rejects_final_junction_to_writable_directory_on_every_test_drive() {
    for temp in drive_letter_temp_dirs() {
        let target = writable_real_directory(temp.path(), "real-home");
        let other_home = temp.path().join("other-home");
        fs::create_dir(&other_home).expect("create other home");
        let alias = other_home.join(".sandbox-bin");
        create_directory_junction(&target, &alias);
        let objects = [(target.as_path(), true), (alias.as_path(), false)];
        let before = snapshot(&objects);

        let result = lock_sandbox_bin(&alias, SANDBOX_BIN_GROUP_MASK);
        let after = snapshot(&objects);
        fs::remove_dir(&alias).expect("remove junction");

        assert_rejected(result, "reparse point");
        assert_eq!(after, before);
    }
}

#[test]
fn rejects_ancestor_junction_to_locked_directory_on_every_test_drive() {
    for temp in drive_letter_temp_dirs() {
        let target = locked_without_write_dac(temp.path(), "real-home", SANDBOX_BIN_GROUP_MASK);
        let linked_home = temp.path().join("linked-home");
        create_directory_junction(target.parent().expect("home"), &linked_home);
        let objects = [(target.as_path(), true), (linked_home.as_path(), false)];
        let before = snapshot(&objects);

        let result = lock_sandbox_bin(&linked_home.join(".sandbox-bin"), SANDBOX_BIN_GROUP_MASK);
        let after = snapshot(&objects);
        fs::remove_dir(&linked_home).expect("remove junction");

        assert_rejected(result, "reparse point");
        assert_eq!(after, before);
    }
}

#[test]
fn rejects_ancestor_junction_to_writable_directory_on_every_test_drive() {
    for temp in drive_letter_temp_dirs() {
        let target = writable_real_directory(temp.path(), "real-home");
        let linked_home = temp.path().join("linked-home");
        create_directory_junction(target.parent().expect("home"), &linked_home);
        let objects = [(target.as_path(), true), (linked_home.as_path(), false)];
        let before = snapshot(&objects);

        let result = lock_sandbox_bin(&linked_home.join(".sandbox-bin"), SANDBOX_BIN_GROUP_MASK);
        let after = snapshot(&objects);
        fs::remove_dir(&linked_home).expect("remove junction");

        assert_rejected(result, "reparse point");
        assert_eq!(after, before);
    }
}

#[test]
fn rejects_directory_symlinks_when_permitted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let target = writable_real_directory(temp.path(), "real-home");
    let other_home = temp.path().join("other-home");
    fs::create_dir(&other_home).expect("create other home");
    let final_link = other_home.join(".sandbox-bin");
    if !try_create_directory_symlink(&target, &final_link) {
        eprintln!("skipping: directory symlink creation is not permitted for this user");
        return;
    }
    let home_link = temp.path().join("linked-home");
    assert!(
        try_create_directory_symlink(target.parent().expect("home"), &home_link),
        "create ancestor directory symlink"
    );
    let objects = [
        (target.as_path(), true),
        (final_link.as_path(), false),
        (home_link.as_path(), false),
    ];
    let before = snapshot(&objects);

    let final_result = lock_sandbox_bin(&final_link, SANDBOX_BIN_GROUP_MASK);
    let ancestor_result = lock_sandbox_bin(&home_link.join(".sandbox-bin"), SANDBOX_BIN_GROUP_MASK);
    let after = snapshot(&objects);
    fs::remove_dir(&final_link).expect("remove final symlink");
    fs::remove_dir(&home_link).expect("remove ancestor symlink");

    assert_rejected(final_result, "reparse point");
    assert_rejected(ancestor_result, "reparse point");
    assert_eq!(after, before);
}

#[test]
fn rejects_volume_mount_point_when_permitted() {
    // A TempDir is not used: its recursive cleanup must never run while a volume
    // is still mounted inside it.
    let root = std::env::temp_dir().join(format!("codex-mount-point-test-{}", std::process::id()));
    let home = root.join("home");
    fs::create_dir_all(&home).expect("create home");
    let (letter, relative) = drive_letter_and_relative(&root);
    let volume = Command::new("mountvol")
        .arg(format!("{letter}:\\"))
        .arg("/L")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|name| name.starts_with(r"\\?\Volume{"));
    let mount = root.join("mounted-volume");
    fs::create_dir(&mount).expect("create mount directory");
    let mount_arg = format!("{}\\", mount.display());
    let mounted = volume.as_ref().is_some_and(|volume| {
        Command::new("mountvol")
            .arg(&mount_arg)
            .arg(volume)
            .output()
            .is_ok_and(|output| output.status.success())
    });
    if !mounted {
        fs::remove_dir_all(&root).expect("cleanup");
        eprintln!("skipping: mounting a volume requires elevation");
        return;
    }
    let objects = [(mount.as_path(), false), (home.as_path(), true)];
    let before = snapshot(&objects);

    let result = lock_sandbox_bin(
        &mount.join(&relative).join("home").join(".sandbox-bin"),
        SANDBOX_BIN_GROUP_MASK,
    );
    let after = snapshot(&objects);
    let unmounted = Command::new("mountvol")
        .arg(&mount_arg)
        .arg("/D")
        .output()
        .is_ok_and(|output| output.status.success());
    assert!(
        unmounted,
        "mount point was not removed; {} left in place",
        root.display()
    );
    let created_through_mount = home.join(".sandbox-bin").exists();
    fs::remove_dir_all(&root).expect("cleanup");

    assert_rejected(result, "reparse point");
    assert_eq!(after, before);
    assert!(
        !created_through_mount,
        "nothing may be created through the mount point"
    );
}

// ---- rejected: drive letters that are not local volume roots ----

#[test]
fn rejects_subst_drive() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir(temp.path().join("home")).expect("create home");
    let letter = unused_drive_letter().expect("an unused drive letter for subst");
    let drive = format!("{letter}:");
    let substituted = Command::new("subst")
        .arg(&drive)
        .arg(temp.path())
        .status()
        .expect("run subst");
    assert!(substituted.success(), "subst {drive} failed");

    let result = lock_sandbox_bin(
        &PathBuf::from(format!(r"{drive}\home\.sandbox-bin")),
        SANDBOX_BIN_GROUP_MASK,
    );
    let _ = Command::new("subst").arg(&drive).arg("/D").status();

    assert_rejected(result, "volume root");
    assert!(!temp.path().join("home").join(".sandbox-bin").exists());
}

#[test]
fn rejects_network_drive_letter_when_mapping_is_permitted() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir(temp.path().join("home")).expect("create home");
    let (letter, relative) = drive_letter_and_relative(temp.path());
    let Some(mapped_letter) = unused_drive_letter() else {
        eprintln!("skipping: mapping a network drive needs an unused drive letter");
        return;
    };
    let drive = format!("{mapped_letter}:");
    let share = format!(r"\\localhost\{letter}$");
    let mapped = Command::new("net")
        .args(["use", &drive, &share, "/persistent:no"])
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|output| output.status.success());
    if !mapped {
        eprintln!("skipping: mapping {share} as a network drive is not permitted for this user");
        return;
    }

    let result = lock_sandbox_bin(
        &PathBuf::from(format!("{drive}\\"))
            .join(&relative)
            .join("home")
            .join(".sandbox-bin"),
        SANDBOX_BIN_GROUP_MASK,
    );
    let _ = Command::new("net")
        .args(["use", &drive, "/delete", "/y"])
        .stdin(Stdio::null())
        .output();

    assert_rejected(result, "local disk volume");
    assert!(!temp.path().join("home").join(".sandbox-bin").exists());
}

#[test]
fn rejects_unc_network_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir(temp.path().join("home")).expect("create home");
    let (letter, relative) = drive_letter_and_relative(temp.path());
    let relative = relative.display();

    for unc in [
        format!(r"\\localhost\{letter}$\{relative}\home\.sandbox-bin"),
        format!(r"\\?\UNC\localhost\{letter}$\{relative}\home\.sandbox-bin"),
    ] {
        assert_rejected(
            lock_sandbox_bin(&PathBuf::from(&unc), SANDBOX_BIN_GROUP_MASK),
            "local disk prefix",
        );
    }

    assert!(!temp.path().join("home").join(".sandbox-bin").exists());
}
