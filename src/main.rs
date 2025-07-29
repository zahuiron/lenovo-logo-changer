use std::fs::{File, remove_dir_all, copy, create_dir_all};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::os::windows::process::CommandExt;
use std::str::FromStr;

use sha2::{Digest, Sha256};
use efivar::efi::{Variable, VariableFlags};
use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::Security::*;

pub fn is_admin() -> bool {
    unsafe {
        let mut token_handle: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            eprintln!("OpenProcessToken failed");
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size: u32 = 0;

        let success = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );

        CloseHandle(token_handle);

        if success == 0 {
            eprintln!("GetTokenInformation failed");
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}

fn find_available_drive() -> Option<char> {
    let drive_mask = unsafe { GetLogicalDrives() };
    for drive_letter in b'A'..=b'Z' {
        let mask = 1 << (drive_letter - b'A');
        if (drive_mask & mask) == 0 {
            return Some(drive_letter as char);
        }
    }
    None
}

fn mountvol_mount(drive_letter: char) -> bool {
    let mut cmd = Command::new("mountvol");
    let status = cmd.arg(format!("{}:", drive_letter))
        .arg("/s")
        .show_window(0u16)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

fn mountvol_unmount(drive_letter: char) -> bool {
    let mut cmd = Command::new("mountvol");
    let status = cmd.arg(format!("{}:", drive_letter))
        .arg("/d")
        .show_window(0u16)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

fn delete_logo_path() -> bool {
    let drive_letter = match find_available_drive() {
        Some(d) => d,
        None => return false,
    };
    if !mountvol_mount(drive_letter) {
        return false;
    }

    let target_path = Path::new(&format!("{}:\\EFI\\Lenovo\\Logo", drive_letter));
    if target_path.exists() {
        if let Err(e) = remove_dir_all(target_path) {
            eprintln!("Failed to remove logo path: {}", e);
            mountvol_unmount(drive_letter);
            return false;
        }
    }
    mountvol_unmount(drive_letter);
    true
}

fn copy_file_to_esp(src: &str, dst: &str) -> bool {
    let src_path = Path::new(src);
    if !src_path.is_file() {
        eprintln!("Source is not file");
        return false;
    }

    let drive_letter = match find_available_drive() {
        Some(d) => d,
        None => return false,
    };
    if !mountvol_mount(drive_letter) {
        return false;
    }

    let target_path = Path::new(&format!("{}:\\", drive_letter)).join(dst);
    if let Some(parent) = target_path.parent() {
        if parent.exists() {
            let _ = remove_dir_all(parent);
        }
        if let Err(e) = create_dir_all(parent) {
            eprintln!("Failed to create target dir: {}", e);
            mountvol_unmount(drive_letter);
            return false;
        }
    }

    if let Err(e) = copy(src, &target_path) {
        eprintln!("Copy file failed: {}", e);
        mountvol_unmount(drive_letter);
        return false;
    }

    mountvol_unmount(drive_letter);
    true
}

fn calculate_sha256(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut sha256 = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        sha256.update(&buffer[..read]);
    }
    Ok(format!("{:x}", sha256.finalize()))
}

pub struct PlatformInfo {
    pub enable: u8,
    pub width: u32,
    pub height: u32,
    pub version: u32,
    pub support: Vec<&'static str>,
    pub lbldesp_var: [u8; 10],
    pub lbldvc_var: [u8; 40],
}

impl Default for PlatformInfo {
    fn default() -> Self {
        Self {
            enable: 0,
            width: 0,
            height: 0,
            version: 0,
            support: vec![],
            lbldesp_var: [0; 10],
            lbldvc_var: [0; 40],
        }
    }
}

impl PlatformInfo {
    pub fn get_info(&mut self) -> bool {
        let varman = efivar::system();
        let esp_var = Variable::from_str("LBLDESP-871455D0-5576-4FB8-9865-AF0824463B9E").unwrap();
        match varman.read(&esp_var) {
            Ok((buffer, _)) => {
                if buffer.len() != 10 {
                    return false;
                }
                self.enable = buffer[0];
                self.width = u32::from_le_bytes(buffer[1..5].try_into().unwrap());
                self.height = u32::from_le_bytes(buffer[5..9].try_into().unwrap());
                self.support = Self::support_format(buffer[9]);
                self.lbldesp_var = buffer.try_into().unwrap();
            }
            Err(_) => return false,
        }

        let dvc_var = Variable::from_str("LBLDVC-871455D1-5576-4FB8-9865-AF0824463C9F").unwrap();
        match varman.read(&dvc_var) {
            Ok((buffer, _)) => {
                if buffer.len() != 40 {
                    return false;
                }
                self.version = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
                self.lbldvc_var = buffer.try_into().unwrap();
            }
            Err(_) => return false,
        }

        true
    }

    pub fn set_logo(&mut self, img_path: &String) -> bool {
        let file_path = Path::new(img_path);
        let ext = file_path.extension().unwrap().to_str().unwrap();
        let dst = format!("EFI/Lenovo/Logo/mylogo_{}x{}.{}", self.width, self.height, ext);

        if !copy_file_to_esp(img_path, &dst) {
            return false;
        }

        let mut varman = efivar::system();
        let mut buffer = self.lbldesp_var;
        buffer[0] = 1;
        let var = Variable::from_str("LBLDESP-871455D0-5576-4FB8-9865-AF0824463B9E").unwrap();
        if varman.write(&var, VariableFlags::from_bits(0x7).unwrap(), &buffer).is_err() {
            return false;
        }
        self.lbldesp_var = buffer;
        self.enable = 1;

        let sha256 = match calculate_sha256(img_path) {
            Ok(s) => hex::decode(s).unwrap(),
            Err(_) => return false,
        };
        let mut dvc_buf = self.lbldvc_var;
        dvc_buf[4..36].copy_from_slice(&sha256);
        let var = Variable::from_str("LBLDVC-871455D1-5576-4FB8-9865-AF0824463C9F").unwrap();
        if varman.write(&var, VariableFlags::from_bits(0x7).unwrap(), &dvc_buf).is_err() {
            return false;
        }
        self.lbldvc_var = dvc_buf;
        true
    }

    pub fn restore_logo(&mut self) -> bool {
        let mut success = true;

        if !delete_logo_path() {
            success = false;
        }

        let mut varman = efivar::system();
        if self.lbldesp_var[0] != 0 {
            let mut buffer = self.lbldesp_var;
            buffer[0] = 0;
            let var = Variable::from_str("LBLDESP-871455D0-5576-4FB8-9865-AF0824463B9E").unwrap();
            if varman.write(&var, VariableFlags::from_bits(0x7).unwrap(), &buffer).is_err() {
                success = false;
            } else {
                self.lbldesp_var = buffer;
                self.enable = 0;
            }
        }

        if self.lbldvc_var[4..40] != [0u8; 36] {
            let mut buffer = self.lbldvc_var;
            buffer[4..40].copy_from_slice(&[0u8; 36]);
            let var = Variable::from_str("LBLDVC-871455D1-5576-4FB8-9865-AF0824463C9F").unwrap();
            if varman.write(&var, VariableFlags::from_bits(0x7).unwrap(), &buffer).is_err() {
                success = false;
            } else {
                self.lbldvc_var = buffer;
            }
        }

        success
    }

    pub fn get_loading_icon(&self) -> bool {
        let output = Command::new("bcdedit")
            .args(["/enum", "all"])
            .show_window(0u16)
            .output();

        match output {
            Ok(out) => {
                let s = String::from_utf8_lossy(&out.stdout);
                !s.lines().any(|line| line.contains("bootuxdisabled") && line.contains("Yes"))
            }
            Err(_) => true,
        }
    }

    pub fn set_loading_icon(&self, show: bool) -> bool {
        let args = if show {
            vec!["-set", "bootuxdisabled", "off"]
        } else {
            vec!["-set", "bootuxdisabled", "on"]
        };

        match Command::new("bcdedit")
            .args(&args)
            .show_window(0u16)
            .output()
        {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    fn support_format(flag: u8) -> Vec<&'static str> {
        let mut out = vec![];
        if flag & 0x01 != 0 { out.push("jpg"); }
        if flag & 0x02 != 0 { out.push("tga"); }
        if flag & 0x04 != 0 { out.push("pcx"); }
        if flag & 0x08 != 0 { out.push("gif"); }
        if flag & 0x10 != 0 { out.push("bmp"); }
        if flag & 0x20 != 0 { out.push("png"); }
        out
    }
}