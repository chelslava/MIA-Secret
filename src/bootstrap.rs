use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

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

    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    Ok(())
}

fn ensure_file(path: &Path) -> Result<(), AppError> {
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    OpenOptions::new().create_new(true).write(true).open(path)?;

    Ok(())
}

fn ensure_random_file(path: &Path, len: usize) -> Result<(), AppError> {
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut bytes = vec![0u8; len];
    fill_random_bytes(&mut bytes)?;

    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(&bytes)?;
    file.flush()?;

    Ok(())
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
                return Err(AppError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("BCryptGenRandom failed with status {status}"),
                )));
            }
            offset += chunk_len;
        }

        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(AppError::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
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
