use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Component;
use std::path::Path;
use std::path::Prefix;
use std::ptr;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_TAG_INFO;
use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::FILE_TRAVERSE;
use windows_sys::Win32::Storage::FileSystem::FileAttributeTagInfo;
use windows_sys::Win32::Storage::FileSystem::FileNameInfo;
use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx;
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK_0;
use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;
use windows_sys::Win32::System::Kernel::OBJ_DONT_REPARSE;

const FILE_OPEN: u32 = 1;
const FILE_OPEN_IF: u32 = 3;
const FILE_DIRECTORY_FILE: u32 = 1;
const STATUS_REPARSE_POINT_ENCOUNTERED: NTSTATUS = 0xC000_050B_u32 as i32;
/// `FILE_INFORMATION_CLASS::FileFsDeviceInformation` for NtQueryVolumeInformationFile.
const FILE_FS_DEVICE_INFORMATION_CLASS: u32 = 4;
const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_DEVICE_VIRTUAL_DISK: u32 = 0x0000_0024;
const FILE_REMOTE_DEVICE: u32 = 0x0000_0010;
/// Reparse tags with this bit redirect name resolution (junctions, symlinks,
/// mount points). See `IsReparseTagNameSurrogate`.
const REPARSE_TAG_NAME_SURROGATE_BIT: u32 = 0x2000_0000;

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

#[repr(C)]
struct FileFsDeviceInformation {
    device_type: u32,
    characteristics: u32,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IO_STATUS_BLOCK,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> NTSTATUS;

    fn NtQueryVolumeInformationFile(
        file_handle: HANDLE,
        io_status_block: *mut IO_STATUS_BLOCK,
        fs_information: *mut c_void,
        length: u32,
        fs_information_class: u32,
    ) -> NTSTATUS;
}

/// Opens or creates the final directory without following a reparse point in
/// any filesystem path component.
///
/// Parent directories must already exist; only the final directory is created.
///
/// The drive letter is resolved by opening the volume root on its own, because
/// `\??\X:` is an object-manager symbolic link and `OBJ_DONT_REPARSE` rejects
/// it on some Windows builds (for example Windows 10 22H2). The root handle is
/// then verified to be the root directory of a local volume, and every
/// filesystem component below it is opened relative to its parent handle with
/// `OBJ_DONT_REPARSE`, so no junction, symlink, or mount point is followed.
///
/// The returned handle must remain open through any security mutation so the
/// mutation stays bound to the directory that passed this validation.
pub(super) fn open_or_create_no_reparse(path: &Path) -> Result<OwnedHandle> {
    let (drive_root, components) = split_local_drive_path(path)?;
    let (last, intermediates) = components.split_last().with_context(|| {
        format!(
            "sandbox ACL path has no directory component: {}",
            path.display()
        )
    })?;

    let mut parent = open_verified_volume_root(&drive_root, path)?;
    for component in intermediates {
        // Each parent handle stays open until its child has been opened, so the
        // relative open is bound to the directory that was just validated.
        parent = open_component(
            &parent,
            component,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            path,
        )?;
    }
    open_component(
        &parent,
        last,
        // SetSecurityInfo can reject a WRITE_DAC-only directory handle.
        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        FILE_OPEN_IF,
        path,
    )
}

/// Splits an absolute local drive path into its NT drive root (`\??\X:\`) and
/// its filesystem components, rejecting every spelling that could change which
/// object is opened.
fn split_local_drive_path(path: &Path) -> Result<(Vec<u16>, Vec<Vec<u16>>)> {
    ensure!(
        path.is_absolute(),
        "sandbox ACL path must be absolute: {}",
        path.display()
    );
    let mut components = path.components();
    let drive_letter = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => bail!(
                "sandbox ACL path must have a local disk prefix: {}",
                path.display()
            ),
        },
        _ => bail!(
            "sandbox ACL path must have a local disk prefix: {}",
            path.display()
        ),
    };
    ensure!(
        drive_letter.is_ascii_alphabetic(),
        "sandbox ACL path has an invalid drive letter: {}",
        path.display()
    );
    ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "sandbox ACL path must be rooted at the drive: {}",
        path.display()
    );

    let mut filesystem_components = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            bail!(
                "sandbox ACL path must not contain `.` or `..` components: {}",
                path.display()
            );
        };
        let name: Vec<u16> = name.encode_wide().collect();
        ensure!(
            is_plain_component(&name),
            "sandbox ACL path has an invalid component: {}",
            path.display()
        );
        filesystem_components.push(name);
    }

    let mut drive_root: Vec<u16> = OsStr::new("\\??\\").encode_wide().collect();
    drive_root.extend([u16::from(drive_letter), u16::from(b':'), u16::from(b'\\')]);
    Ok((drive_root, filesystem_components))
}

/// A component is opened as a single relative name, so it must not contain a
/// separator, a stream/device delimiter, or a NUL, and must not be `.`/`..`
/// (verbatim paths do not normalize those).
fn is_plain_component(name: &[u16]) -> bool {
    let dot = u16::from(b'.');
    !name.is_empty()
        && name != [dot]
        && name != [dot, dot]
        && !name
            .iter()
            .any(|&unit| matches!(unit, 0 | 0x2F /* / */ | 0x3A /* : */ | 0x5C /* \ */))
}

/// Opens `\??\X:\` so the object manager resolves the drive letter, then proves
/// through the returned handle that it is the root directory of a local volume
/// and not a reparse point. A drive letter redirected into a subdirectory (for
/// example with `subst`) or to a network share is rejected.
fn open_verified_volume_root(drive_root: &[u16], path: &Path) -> Result<OwnedHandle> {
    let root = nt_open(
        None,
        drive_root,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        OBJ_CASE_INSENSITIVE as u32,
        path,
    )?;

    let mut device = FileFsDeviceInformation {
        device_type: 0,
        characteristics: 0,
    };
    let mut io_status_block = empty_io_status_block();
    let status = unsafe {
        NtQueryVolumeInformationFile(
            root.as_raw_handle() as HANDLE,
            &mut io_status_block,
            (&mut device as *mut FileFsDeviceInformation).cast(),
            size_of::<FileFsDeviceInformation>() as u32,
            FILE_FS_DEVICE_INFORMATION_CLASS,
        )
    };
    if status < 0 {
        return Err(nt_status_error(status))
            .with_context(|| format!("query sandbox ACL drive device {}", path.display()));
    }
    ensure!(
        matches!(
            device.device_type,
            FILE_DEVICE_DISK | FILE_DEVICE_VIRTUAL_DISK
        ) && device.characteristics & FILE_REMOTE_DEVICE == 0,
        "sandbox ACL path must be on a local disk volume: {}",
        path.display()
    );

    ensure!(
        handle_volume_relative_name(&root)? == [u16::from(b'\\')],
        "sandbox ACL drive letter does not resolve to a volume root: {}",
        path.display()
    );
    reject_name_surrogate(&root, path)?;
    Ok(root)
}

fn open_component(
    parent: &OwnedHandle,
    name: &[u16],
    desired_access: u32,
    create_disposition: u32,
    path: &Path,
) -> Result<OwnedHandle> {
    let handle = nt_open(
        Some(parent),
        name,
        desired_access,
        create_disposition,
        OBJ_CASE_INSENSITIVE as u32 | OBJ_DONT_REPARSE as u32,
        path,
    )?;
    // OBJ_DONT_REPARSE already fails on a followed reparse point; this keeps the
    // guarantee explicit for the handle that is actually returned.
    reject_name_surrogate(&handle, path)?;
    Ok(handle)
}

fn nt_open(
    root_directory: Option<&OwnedHandle>,
    name: &[u16],
    desired_access: u32,
    create_disposition: u32,
    attributes: u32,
    path: &Path,
) -> Result<OwnedHandle> {
    let mut buffer: Vec<u16> = name.to_vec();
    buffer.push(0);
    let name_length =
        u16::try_from(name.len() * size_of::<u16>()).context("sandbox ACL path is too long")?;
    let maximum_length =
        u16::try_from(buffer.len() * size_of::<u16>()).context("sandbox ACL path is too long")?;
    let object_name = UNICODE_STRING {
        Length: name_length,
        MaximumLength: maximum_length,
        Buffer: buffer.as_mut_ptr(),
    };
    let object_attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: root_directory.map_or(0, |handle| handle.as_raw_handle() as HANDLE),
        object_name: &object_name,
        attributes,
        security_descriptor: ptr::null(),
        security_quality_of_service: ptr::null(),
    };
    let mut io_status_block = empty_io_status_block();
    let mut handle = 0;
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &object_attributes,
            &mut io_status_block,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            create_disposition,
            FILE_DIRECTORY_FILE,
            ptr::null(),
            /*ea_length*/ 0,
        )
    };
    if status < 0 {
        if status == STATUS_REPARSE_POINT_ENCOUNTERED {
            bail!(
                "sandbox ACL path contains a reparse point: {}",
                path.display()
            );
        }
        return Err(nt_status_error(status))
            .with_context(|| format!("open sandbox ACL directory {}", path.display()));
    }
    ensure!(
        handle != 0 && handle != INVALID_HANDLE_VALUE,
        "NtCreateFile returned an invalid sandbox ACL directory handle"
    );
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as *mut c_void) })
}

fn reject_name_surrogate(handle: &OwnedHandle, path: &Path) -> Result<()> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("query sandbox ACL directory attributes {}", path.display()));
    }
    ensure!(
        info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || info.ReparseTag & REPARSE_TAG_NAME_SURROGATE_BIT == 0,
        "sandbox ACL path contains a reparse point: {}",
        path.display()
    );
    Ok(())
}

/// Returns the handle's path relative to its volume (`\` for a volume root).
fn handle_volume_relative_name(handle: &OwnedHandle) -> Result<Vec<u16>> {
    // FILE_NAME_INFO is { u32 FileNameLength; [u16; 1] FileName }.
    let mut buffer = vec![0u8; size_of::<u32>() + 1024 * size_of::<u16>()];
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileNameInfo,
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).context("file name buffer is too large")?,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("query sandbox ACL drive root name");
    }
    let name_bytes = u32::from_ne_bytes(buffer[..size_of::<u32>()].try_into()?) as usize;
    let name = buffer
        .get(size_of::<u32>()..size_of::<u32>() + name_bytes)
        .context("sandbox ACL drive root name is truncated")?;
    Ok(name
        .chunks_exact(size_of::<u16>())
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect())
}

fn empty_io_status_block() -> IO_STATUS_BLOCK {
    IO_STATUS_BLOCK {
        Anonymous: IO_STATUS_BLOCK_0 { Status: 0 },
        Information: 0,
    }
}

fn nt_status_error(status: NTSTATUS) -> std::io::Error {
    let error = unsafe { RtlNtStatusToDosError(status) };
    std::io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
#[path = "no_reparse_dir_tests.rs"]
mod tests;
