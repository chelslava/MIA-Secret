use std::fs::{self, OpenOptions};
#[cfg(any(unix, not(windows)))]
use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::config::Config;
use crate::error::AppError;

const MASTER_KEY_FILE_NAME: &str = "master.key";
const MASTER_KEY_LEN: usize = 32;

pub fn ensure_layout(cfg: &Config) -> Result<(), AppError> {
    let data_dir = PathBuf::from(&cfg.general.data_dir);
    fs::create_dir_all(&data_dir)?;

    ensure_parent_dir(Path::new(&cfg.general.database_path))?;
    ensure_file(Path::new(&cfg.general.database_path))?;

    let master_key_path = data_dir.join(MASTER_KEY_FILE_NAME);
    ensure_random_file(&master_key_path, MASTER_KEY_LEN)?;
    secure_master_key_permissions(&master_key_path)?;

    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), AppError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn ensure_file(path: &Path) -> Result<(), AppError> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create_new(true).write(true).open(path)?;
    Ok(())
}

fn ensure_random_file(path: &Path, len: usize) -> Result<(), AppError> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut bytes = vec![0u8; len];
    fill_random_bytes(&mut bytes)?;

    #[cfg(windows)]
    {
        create_secure_file_windows(path, &bytes)?;
        bytes.zeroize();
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&bytes)?;
        file.flush()?;
        bytes.zeroize();
        return Ok(());
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
        file.write_all(&bytes)?;
        file.flush()?;
        bytes.zeroize();
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(AppError::Server(
        "secure file creation is not supported on this platform".to_owned(),
    ))
}

fn secure_master_key_permissions(path: &Path) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    #[cfg(windows)]
    {
        secure_master_key_permissions_windows(path)?;
    }

    Ok(())
}

#[cfg(windows)]
fn secure_master_key_permissions_windows(path: &Path) -> Result<(), AppError> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl};

    let current_user_sid = get_current_user_sid_string()?;
    if verify_master_key_acl(path, &current_user_sid).is_ok() {
        return Ok(());
    }

    let sddl = format!("D:P(A;;GRGW;;;{current_user_sid})(A;;FA;;;SY)");
    let sddl_wide = to_wide_nul(&sddl);
    let path_wide = to_wide_nul(path.to_string_lossy().as_ref());

    let mut security_descriptor = std::ptr::null_mut();
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        )
    };
    if parsed == 0 || security_descriptor.is_null() {
        return Err(AppError::Server(format!(
            "failed to parse ACL SDDL (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let mut dacl_present = 0i32;
    let mut dacl_defaulted = 0i32;
    let mut dacl = std::ptr::null_mut();
    let dacl_ok = unsafe {
        GetSecurityDescriptorDacl(
            security_descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if dacl_ok == 0 || dacl_present == 0 || dacl.is_null() {
        unsafe {
            let _ = LocalFree(security_descriptor);
        }
        return Err(AppError::Server(format!(
            "failed to extract DACL from security descriptor (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let applied = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        let _ = LocalFree(security_descriptor);
    }
    if applied != 0 {
        return Err(AppError::Server(format!(
            "failed to set ACL on {} (SetNamedSecurityInfoW code={})",
            path.display(),
            applied
        )));
    }

    verify_master_key_acl(path, &current_user_sid)
}

#[cfg(windows)]
fn create_secure_file_windows(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        WriteFile,
    };

    let current_user_sid = get_current_user_sid_string()?;
    let sddl = format!("D:P(A;;GRGW;;;{current_user_sid})(A;;FA;;;SY)");
    let sddl_wide = to_wide_nul(&sddl);
    let path_wide = to_wide_nul(path.to_string_lossy().as_ref());

    let mut security_descriptor = std::ptr::null_mut();
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        )
    };
    if parsed == 0 || security_descriptor.is_null() {
        return Err(AppError::Server(format!(
            "failed to parse ACL SDDL for secure file creation (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor,
        bInheritHandle: 0,
    };

    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        unsafe {
            let _ = LocalFree(security_descriptor);
        }
        return Err(AppError::Server(format!(
            "CreateFileW failed for {} (GetLastError={})",
            path.display(),
            unsafe { GetLastError() }
        )));
    }

    let mut written = 0u32;
    let write_ok = unsafe {
        WriteFile(
            handle,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        let _ = LocalFree(security_descriptor);
        let _ = CloseHandle(handle);
    }
    if write_ok == 0 || written != bytes.len() as u32 {
        return Err(AppError::Server(format!(
            "WriteFile failed for {} (GetLastError={})",
            path.display(),
            unsafe { GetLastError() }
        )));
    }

    Ok(())
}

#[cfg(windows)]
fn verify_master_key_acl(path: &Path, current_user_sid: &str) -> Result<(), AppError> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    let path_wide = to_wide_nul(path.to_string_lossy().as_ref());
    let mut security_descriptor = std::ptr::null_mut();
    let get_result = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if get_result != ERROR_SUCCESS {
        return Err(AppError::Server(format!(
            "failed to read ACL for {} (code {})",
            path.display(),
            get_result
        )));
    }

    let mut sddl_ptr: *mut u16 = std::ptr::null_mut();
    let to_sddl = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl_ptr,
            std::ptr::null_mut(),
        )
    };
    if to_sddl == 0 || sddl_ptr.is_null() {
        unsafe {
            let _ = LocalFree(security_descriptor);
        }
        return Err(AppError::Server("failed to convert ACL to SDDL".to_owned()));
    }

    let sddl = pwstr_to_string(sddl_ptr);
    unsafe {
        let _ = LocalFree(sddl_ptr as *mut _);
        let _ = LocalFree(security_descriptor);
    }

    if !sddl.contains(current_user_sid) {
        return Err(AppError::Server(format!(
            "ACL validation failed: current user SID is missing for {}",
            path.display()
        )));
    }
    if sddl.contains(";;;WD)") || sddl.contains(";;;AU)") || sddl.contains(";;;BU)") {
        return Err(AppError::Server(format!(
            "ACL validation failed: insecure principal is present for {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn get_current_user_sid_string() -> Result<String, AppError> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    let open_ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if open_ok == 0 {
        return Err(AppError::Server(format!(
            "OpenProcessToken failed (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let mut token_info_len = 0u32;
    let _ = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut token_info_len,
        )
    };
    if token_info_len == 0 {
        unsafe {
            let _ = CloseHandle(token);
        }
        return Err(AppError::Server(
            "GetTokenInformation returned zero length".to_owned(),
        ));
    }

    let mut buffer = vec![0u8; token_info_len as usize];
    let info_ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut _,
            token_info_len,
            &mut token_info_len,
        )
    };
    if info_ok == 0 {
        unsafe {
            let _ = CloseHandle(token);
        }
        return Err(AppError::Server(format!(
            "GetTokenInformation(TokenUser) failed (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let mut sid_ptr: *mut u16 = std::ptr::null_mut();
    let sid_ok = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_ptr) };
    if sid_ok == 0 || sid_ptr.is_null() {
        unsafe {
            let _ = CloseHandle(token);
        }
        return Err(AppError::Server(format!(
            "ConvertSidToStringSidW failed (GetLastError={})",
            unsafe { GetLastError() }
        )));
    }

    let sid = pwstr_to_string(sid_ptr);
    unsafe {
        let _ = LocalFree(sid_ptr as *mut _);
        let _ = CloseHandle(token);
    }
    Ok(sid)
}

#[cfg(windows)]
fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn pwstr_to_string(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn fill_random_bytes(buffer: &mut [u8]) -> Result<(), AppError> {
    #[cfg(target_family = "unix")]
    {
        use std::io::Read;
        let mut file = fs::File::open("/dev/urandom")?;
        file.read_exact(buffer)?;
        return Ok(());
    }

    #[cfg(target_family = "windows")]
    {
        let mut offset = 0usize;
        while offset < buffer.len() {
            let remaining = buffer.len() - offset;
            let chunk_len = remaining.min(u32::MAX as usize);
            let status = unsafe {
                bcrypt_gen_random(
                    buffer[offset..offset + chunk_len].as_mut_ptr(),
                    chunk_len as u32,
                )
            };
            if status != 0 {
                return Err(AppError::Io(std::io::Error::other(format!(
                    "BCryptGenRandom failed with status {status}"
                ))));
            }
            offset += chunk_len;
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(AppError::Io(std::io::Error::other(
        "random byte generation is not supported on this platform",
    )))
}

#[cfg(target_family = "windows")]
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(hAlgorithm: isize, pbBuffer: *mut u8, cbBuffer: u32, dwFlags: u32) -> i32;
}

#[cfg(target_family = "windows")]
unsafe fn bcrypt_gen_random(buffer: *mut u8, len: u32) -> i32 {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    unsafe { BCryptGenRandom(0, buffer, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
}
