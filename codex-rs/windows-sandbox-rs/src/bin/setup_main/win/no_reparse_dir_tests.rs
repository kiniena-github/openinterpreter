use std::fs;
use std::fs::File;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use pretty_assertions::assert_eq;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;

use super::open_or_create_no_reparse;
use super::split_local_drive_path;

/// Set to a writable directory on another drive (for example
/// `D:\AI\OpenInterpreter-Fix\target\no-reparse-drive-test`) to repeat the
/// drive-letter regression tests on that volume.
const EXTRA_DRIVE_TEST_ROOT_ENV: &str = "CODEX_NO_REPARSE_TEST_ROOT";

fn create_directory_junction(target: &Path, alias: &Path) -> Result<()> {
    let output = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(alias)
        .arg(target)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "mklink /J failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Directory symlinks need SeCreateSymbolicLinkPrivilege or Developer Mode, so
/// callers skip when creation is not permitted.
fn try_create_directory_symlink(target: &Path, alias: &Path) -> Result<bool> {
    let output = Command::new("cmd")
        .args(["/C", "mklink", "/D"])
        .arg(alias)
        .arg(target)
        .output()?;
    Ok(output.status.success())
}

/// Temporary directories on the default temp volume plus, when configured, on
/// the extra drive root. Every returned path is a drive-letter path.
fn drive_letter_temp_dirs() -> Result<Vec<tempfile::TempDir>> {
    let mut dirs = vec![tempfile::tempdir()?];
    if let Some(root) = std::env::var_os(EXTRA_DRIVE_TEST_ROOT_ENV) {
        let root = PathBuf::from(root);
        fs::create_dir_all(&root)?;
        dirs.push(tempfile::tempdir_in(root)?);
    }
    Ok(dirs)
}

fn file_identity(handle: HANDLE) -> Result<(u32, u32, u32)> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

fn identity_of_path(path: &Path) -> Result<(u32, u32, u32)> {
    let file = File::options()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    file_identity(file.as_raw_handle() as HANDLE)
}

fn identity_of_handle(handle: &OwnedHandle) -> Result<(u32, u32, u32)> {
    file_identity(handle.as_raw_handle() as HANDLE)
}

#[test]
fn creates_and_opens_plain_directory_leaf() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join(".sandbox-bin");

    drop(open_or_create_no_reparse(&directory)?);
    let _handle = open_or_create_no_reparse(&directory)?;

    assert!(directory.is_dir());
    Ok(())
}

#[test]
fn rejects_final_directory_junction() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let target = temporary.path().join("target");
    let alias = temporary.path().join(".sandbox-bin");
    fs::create_dir(&target)?;
    create_directory_junction(&target, &alias)?;

    let _ =
        open_or_create_no_reparse(&alias).expect_err("final directory junction must be rejected");
    fs::remove_dir(&alias)?;
    Ok(())
}

#[test]
fn rejects_ancestor_directory_junction() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let target_home = temporary.path().join("target-home");
    let alias_home = temporary.path().join("linked-home");
    fs::create_dir(&target_home)?;
    fs::create_dir(target_home.join(".sandbox-bin"))?;
    create_directory_junction(&target_home, &alias_home)?;

    let _ = open_or_create_no_reparse(&alias_home.join(".sandbox-bin"))
        .expect_err("ancestor directory junction must be rejected");
    fs::remove_dir(&alias_home)?;
    Ok(())
}

// Regression: on Windows 10 22H2 `\??\X:` is an object-manager symbolic link and
// an absolute OBJ_DONT_REPARSE open failed with STATUS_REPARSE_POINT_ENCOUNTERED
// for every drive-letter path, even when every directory was a normal directory.

#[test]
fn creates_plain_directory_on_drive_letter_path() -> Result<()> {
    for temporary in drive_letter_temp_dirs()? {
        let directory = temporary.path().join("home").join(".sandbox-bin");
        fs::create_dir(temporary.path().join("home"))?;
        assert!(directory.components().next().is_some_and(|component| matches!(
            component,
            std::path::Component::Prefix(prefix)
                if matches!(prefix.kind(), std::path::Prefix::Disk(_))
        )));

        let handle = open_or_create_no_reparse(&directory)?;

        assert!(directory.is_dir());
        assert_eq!(identity_of_handle(&handle)?, identity_of_path(&directory)?);
    }
    Ok(())
}

#[test]
fn opens_existing_plain_directory() -> Result<()> {
    for temporary in drive_letter_temp_dirs()? {
        let directory = temporary.path().join(".sandbox-bin");
        fs::create_dir(&directory)?;
        let marker = directory.join("existing.txt");
        fs::write(&marker, b"kept")?;

        let handle = open_or_create_no_reparse(&directory)?;

        assert_eq!(identity_of_handle(&handle)?, identity_of_path(&directory)?);
        assert_eq!(fs::read(&marker)?, b"kept".to_vec());
    }
    Ok(())
}

#[test]
fn opens_multiple_nested_plain_directories() -> Result<()> {
    for temporary in drive_letter_temp_dirs()? {
        let parent = temporary
            .path()
            .join("AI")
            .join("OpenInterpreter")
            .join("home");
        fs::create_dir_all(&parent)?;
        let directory = parent.join(".sandbox-bin");

        let handle = open_or_create_no_reparse(&directory)?;

        assert_eq!(identity_of_handle(&handle)?, identity_of_path(&directory)?);
    }
    Ok(())
}

#[test]
fn verbatim_drive_path_opens_same_directory() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join(".sandbox-bin");
    fs::create_dir(&directory)?;
    let verbatim = PathBuf::from(format!(r"\\?\{}", directory.display()));

    let handle = open_or_create_no_reparse(&verbatim)?;

    assert_eq!(identity_of_handle(&handle)?, identity_of_path(&directory)?);
    Ok(())
}

#[test]
fn rejects_final_directory_junction_on_every_test_drive() -> Result<()> {
    for temporary in drive_letter_temp_dirs()? {
        let target = temporary.path().join("target");
        let alias = temporary.path().join(".sandbox-bin");
        fs::create_dir(&target)?;
        create_directory_junction(&target, &alias)?;

        let error = open_or_create_no_reparse(&alias)
            .expect_err("final directory junction must be rejected");
        assert!(
            format!("{error:#}").contains("reparse point"),
            "unexpected error: {error:#}"
        );
        assert!(
            fs::read_dir(&target)?.next().is_none(),
            "nothing may be created through the junction"
        );
        fs::remove_dir(&alias)?;
    }
    Ok(())
}

#[test]
fn rejects_deep_ancestor_directory_junction_on_every_test_drive() -> Result<()> {
    for temporary in drive_letter_temp_dirs()? {
        let real = temporary.path().join("real");
        fs::create_dir_all(real.join("OpenInterpreter").join("home"))?;
        let linked = temporary.path().join("linked");
        create_directory_junction(&real, &linked)?;
        let directory = linked.join("OpenInterpreter").join("home").join(".sandbox-bin");

        let error = open_or_create_no_reparse(&directory)
            .expect_err("ancestor directory junction must be rejected");
        assert!(
            format!("{error:#}").contains("reparse point"),
            "unexpected error: {error:#}"
        );
        assert!(
            !real.join("OpenInterpreter").join("home").join(".sandbox-bin").exists(),
            "the final directory must not be created through the junction"
        );
        fs::remove_dir(&linked)?;
    }
    Ok(())
}

#[test]
fn rejects_directory_symlink_component_when_symlinks_are_permitted() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let real = temporary.path().join("real");
    fs::create_dir_all(real.join("home"))?;
    let linked = temporary.path().join("linked");
    if !try_create_directory_symlink(&real, &linked)? {
        eprintln!("skipping: directory symlink creation is not permitted for this user");
        return Ok(());
    }

    let _ = open_or_create_no_reparse(&linked.join("home").join(".sandbox-bin"))
        .expect_err("directory symlink component must be rejected");
    let _ = open_or_create_no_reparse(&linked)
        .expect_err("final directory symlink must be rejected");
    assert!(!real.join("home").join(".sandbox-bin").exists());
    fs::remove_dir(&linked)?;
    Ok(())
}

#[test]
fn rejects_drive_letter_that_does_not_map_to_a_volume_root() -> Result<()> {
    // `subst` maps a drive letter to a directory for the current logon session
    // without elevation; that mapping must not stand in for a volume root.
    let temporary = tempfile::tempdir()?;
    fs::create_dir(temporary.path().join("home"))?;
    let Some(letter) = ('M'..='Z')
        .rev()
        .find(|letter| !Path::new(&format!("{letter}:\\")).exists())
    else {
        eprintln!("skipping: no unused drive letter for subst");
        return Ok(());
    };
    let drive = format!("{letter}:");
    let status = Command::new("subst")
        .arg(&drive)
        .arg(temporary.path())
        .status()?;
    if !status.success() {
        eprintln!("skipping: subst {drive} failed");
        return Ok(());
    }

    let result = open_or_create_no_reparse(&PathBuf::from(format!(r"{drive}\home\.sandbox-bin")));
    let _ = Command::new("subst").arg(&drive).arg("/D").status();

    let error = result.expect_err("a subst drive must not be accepted as a volume root");
    assert!(
        format!("{error:#}").contains("volume root"),
        "unexpected error: {error:#}"
    );
    assert!(!temporary.path().join("home").join(".sandbox-bin").exists());
    Ok(())
}

#[test]
fn rejects_non_local_or_non_normalized_paths() {
    for rejected in [
        r"relative\.sandbox-bin",
        r"C:relative\.sandbox-bin",
        r"\\server\share\.sandbox-bin",
        r"\\?\UNC\server\share\.sandbox-bin",
        r"C:\home\..\.sandbox-bin",
        r"\\?\C:\home\..\.sandbox-bin",
        r"\\?\C:\home\.\.sandbox-bin",
        r"C:\home\.sandbox-bin:stream",
        r"\\?\C:\home/.sandbox-bin",
        r"C:\",
    ] {
        assert!(
            split_local_drive_path(Path::new(rejected))
                .and_then(|(_, components)| {
                    anyhow::ensure!(!components.is_empty(), "no components");
                    Ok(())
                })
                .is_err(),
            "path must be rejected: {rejected}"
        );
    }
}

#[test]
fn splits_drive_root_from_filesystem_components() -> Result<()> {
    let (root, components) =
        split_local_drive_path(Path::new(r"D:\AI\OpenInterpreter\home\.sandbox-bin"))?;

    assert_eq!(String::from_utf16(&root)?, r"\??\D:\");
    assert_eq!(
        components
            .iter()
            .map(Vec::as_slice)
            .map(String::from_utf16)
            .collect::<Result<Vec<_>, _>>()?,
        vec!["AI", "OpenInterpreter", "home", ".sandbox-bin"]
    );
    Ok(())
}
