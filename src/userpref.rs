use std::{
    io::{Error, ErrorKind},
    path::Path,
    ptr::null_mut,
};
use winreg::{enums::*, RegKey};

/// Easily override user prefs
#[cfg(windows)]
pub struct UserPref {
    is_win_10: bool,
    is_win_8_1: bool,
    is_win_10_update_1607_or_below: bool,
    sid: String,
    key: RegKey,
}

#[cfg(windows)]
impl UserPref {
    /// Create a new instance of userpref
    pub fn new(key: RegKey) -> Result<UserPref, Error> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        // Get CurrentVersion key
        let current_version = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")?;

        // Determine windows version
        let is_win_10 = current_version
            .get_value::<u32, _>("CurrentMajorVersionNumber")
            .is_ok();
        let is_win_8_1 = if is_win_10 {
            false
        } else {
            current_version
                .get_value::<String, _>("CurrentVersion")
                .ok()
                .map_or(false, |v| v == "6")
        };
        let is_win_10_update_1607_or_below = is_win_8_1
            || current_version
                .get_value::<String, _>("ReleaseId")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .map_or(false, |v| v <= 1607);

        // Get sid
        let sid = get_user_sid()?;

        Ok(UserPref {
            is_win_10,
            is_win_8_1,
            is_win_10_update_1607_or_below,
            sid,
            key,
        })
    }

    /// Requires Hashing
    ///   Only force userpref hash on windows 8 and 10
    pub fn requires_hash(&self) -> bool { self.is_win_8_1 || self.is_win_10 }

    /// Requires executable path
    pub fn requires_executable_path(&self) -> bool { self.is_win_10_update_1607_or_below }

    /// Force change ProgId and Hash of userpref in a specific location in registry:
    ///   Where the registry path to userpref is: {address}\{protocol}\UserChoice
    ///   prog_id as a subkey of KEY_CLASSES_ROOT that MUST have a shell\open\command
    pub fn change(&self, address: &str, protocol: &str, prog_id: &str) -> Result<&UserPref, Error> {
        let address = Path::new(address).join(protocol).join("UserChoice");

        // First delete original default browser key (if it even exists) and recreate it
        let _ = self.key.delete_subkey(&address);
        let (default_browser_key, _) = self.key.create_subkey(&address)?;

        // Set new default program
        default_browser_key.set_value("ProgId", &prog_id)?;

        // Hash only required on some versions of windows
        if self.requires_hash() {
            // Hash input starts with file ext, then user sid, default ProgId, and browser
            // path
            let mut input = String::new();
            input.push_str(&protocol);
            input.push_str(&self.sid);
            input.push_str(&prog_id);

            // Push executable_path to hash as long as the protocol is shell url (so it is
            // not a file extension starting with a period)
            if self.requires_executable_path() && protocol.starts_with('.') {
                input.push_str(&get_executable_path_from_app_id(&prog_id));
            }

            // Push registry write time
            if self.is_win_10 {
                input.push_str(&get_registry_last_write_time(&default_browser_key)?);
                input.push_str("User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}");
            }

            // Set hash
            default_browser_key.set_value("Hash", &hash_from_string(input))?;
        }

        Ok(self)
    }
}

#[cfg(windows)]
impl Drop for UserPref {
    /// Done setting userpref so reload desktop icons
    fn drop(&mut self) {
        use winapi::shared::minwindef::LPCVOID;
        extern "system" {
            pub fn SHChangeNotify(wEventId: i32, uFlags: u32, dwItem1: LPCVOID, dwItem2: LPCVOID);
        }

        // Shell icons changed
        unsafe {
            SHChangeNotify(0x0800_0000, 0, 0 as _, 0 as _);
        }
    }
}

// Combines four u8 in order to create a u32
#[cfg(target_endian = "little")]
#[inline(always)]
fn u32_from_u8(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((d as u32) << 24) | ((c as u32) << 16) | ((b as u32) << 8) | (a as u32)
}

/// Generates 64 bit hash
#[allow(clippy::cast_ptr_alignment)]
fn hash(mut input: Vec<u8>) -> String {
    use crypto::{digest::Digest, md5::Md5};
    use std::num::Wrapping;

    // Add utf-16 null character
    input.push(0);
    input.push(0);

    // Compute md5 hash
    let mut md5 = [0; 16];
    let mut hasher = Md5::new();
    hasher.input(&input);
    hasher.result(&mut md5);

    // We only care about the first half of the md5 hash
    let md5_1 = Wrapping(u32_from_u8(md5[0], md5[1], md5[2], md5[3]) | 1);
    let md5_2 = Wrapping(u32_from_u8(md5[4], md5[5], md5[6], md5[7]) | 1);
    let md5_3 = md5_1 + Wrapping(1_778_057_216);
    let md5_4 = md5_2 + Wrapping(333_119_488);

    // Pass through simple proprietary hashing algorithm relying on integer overflow
    let mut p1 = Wrapping(0);
    let mut p2 = Wrapping(0);
    let mut p3 = Wrapping(0);
    let mut p4 = Wrapping(0);

    // Group by 32-bit characters
    let input_as_u32 = unsafe {
        std::slice::from_raw_parts(input.as_ptr() as *const u32, input.len() / 4).to_vec()
    };

    // Iterate utf16 encoded string 2 characters at a time
    for (char1, char2) in input_as_u32
        .chunks_exact(2)
        .map(|words| (Wrapping(words[0]), Wrapping(words[1])))
    {
        // Many magic numbers
        let v0 = char1 + p1;
        let v1 = md5_3 * v0 + Wrapping(4_010_109_435) * (v0 >> 16);
        let v2 = Wrapping(2_046_337_941) * v1 + Wrapping(1_755_016_095) * (v1 >> 16);
        let v3 = Wrapping(3_935_764_481) * v2 + Wrapping(3_287_280_279) * (v2 >> 16);
        let v4 = char2 + v3;
        let v5 = md5_4 * v4 + Wrapping(3_273_069_531) * (v4 >> 16);
        let v6 = Wrapping(1_505_996_589) * v5 + Wrapping(3_721_207_567) * (v5 >> 16);
        p1 = Wrapping(516_489_217) * v6 + Wrapping(901_586_633) * (v6 >> 16);
        p2 += p1 + v3;

        // Even more magic numbers
        let v0 = md5_1 * (char1 + p3);
        let v1 = Wrapping(2_970_681_344) * v0 + Wrapping(3_482_890_513) * (v0 >> 16);
        let v2 = Wrapping(1_537_146_880) * v1 + Wrapping(2_265_471_903) * (v1 >> 16);
        let v3 = Wrapping(3_110_928_384) * v2 + Wrapping(315_537_773) * (v2 >> 16);
        let v4 = Wrapping(495_124_480) * v3 + Wrapping(629_022_083) * (v3 >> 16);
        let v5 = md5_2 * (char2 + v4);
        let v6 = Wrapping(385_155_072) * v5 + Wrapping(2_725_517_045) * (v5 >> 16);
        let v7 = Wrapping(2_533_294_080) * v6 + Wrapping(3_548_616_447) * (v6 >> 16);
        let v8 = Wrapping(730_398_720) * v7 + Wrapping(2_090_019_721) * (v7 >> 16);
        p3 = Wrapping(2_674_458_624) * v8 + Wrapping(3_215_236_969) * (v8 >> 16);
        p4 += p3 + v4;
    }

    // Hash is a 64 bit value which is a combination of the numbers we obtained earlier
    let hash = unsafe { std::mem::transmute::<[u32; 2], [u8; 8]>([p1.0 ^ p3.0, p2.0 ^ p4.0]) };

    // Final hash is the base64 encoding of said 64 bit hash
    base64::encode(&hash)
}

/// Generates our hash from a string
fn hash_from_string(input: String) -> String {
    // Case insensitive
    let input = input.to_lowercase();

    // Convert input string into a utf-16 encoded null-terminated vector
    let utf16: Vec<u16> = input.encode_utf16().collect();

    // Convert input string into a u8 vector
    let input: Vec<u8> = unsafe {
        std::slice::from_raw_parts(utf16.as_ptr() as *const u8, utf16.len() * 2).to_vec()
    };

    hash(input)
}

/// Gets the last write time of a registry entry as a string
fn get_registry_last_write_time(lp_sub_key: &RegKey) -> Result<String, Error> {
    use winapi::{
        shared::minwindef::FILETIME,
        um::{
            minwinbase::SYSTEMTIME,
            timezoneapi::{FileTimeToSystemTime, SystemTimeToFileTime},
            winreg::RegQueryInfoKeyW,
        },
    };

    // Get date registry key was created
    let mut ft_last_write_time = FILETIME {
        dwHighDateTime: 0,
        dwLowDateTime: 0,
    };
    unsafe {
        RegQueryInfoKeyW(
            lp_sub_key.raw_handle(),
            0 as _,
            0 as _,
            0 as _,
            0 as _,
            0 as _,
            0 as _,
            0 as _,
            0 as _,
            0 as _,
            0 as _,
            &mut ft_last_write_time,
        );
    }

    // 0 seconds and milliseconds and convert back to file time
    let mut system_time = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    unsafe {
        FileTimeToSystemTime(&ft_last_write_time, &mut system_time);
    }
    system_time.wSecond = 0;
    system_time.wMilliseconds = 0;
    unsafe {
        SystemTimeToFileTime(&system_time, &mut ft_last_write_time);
    }

    // return the date
    Ok(format!(
        "{:08x}{:08x}",
        ft_last_write_time.dwHighDateTime, ft_last_write_time.dwLowDateTime
    ))
}

/// Gets current user's SID
/// Based on Giovanni's code from https://social.msdn.microsoft.com/Forums/lync/en-US/6b23fff0-773b-4065-bc3f-d88ce6c81eb0/get-user-sid-in-unmanaged-c#answers
fn get_user_sid() -> Result<String, Error> {
    // Imports
    use widestring::U16CString;
    use winapi::{
        shared::{
            minwindef::{BYTE, DWORD},
            sddl::ConvertSidToStringSidW,
            winerror::*,
        },
        um::{
            errhandlingapi::GetLastError,
            handleapi::CloseHandle,
            processthreadsapi::{GetCurrentProcess, OpenProcessToken},
            securitybaseapi::GetTokenInformation,
            winbase::LocalFree,
            winnt::{TokenUser, HANDLE, LPWSTR, PTOKEN_USER, TOKEN_QUERY},
        },
    };

    let mut sid = Err(Error::new(ErrorKind::Other, "Could not get SID"));

    unsafe {
        // Open the access token associated with the calling process
        let mut h_token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token) == 1 {
            // Get the size of the memory buffer needed for the SID. Ignore
            // ERROR_INSUFFICIENT_BUFFER error
            let mut dw_buffer_size: DWORD = 0;
            if GetTokenInformation(h_token, TokenUser, null_mut(), 0, &mut dw_buffer_size) == 1
                || GetLastError() == ERROR_INSUFFICIENT_BUFFER
            {
                // Allocate buffer for user token data
                let mut buffer = Vec::<BYTE>::with_capacity(dw_buffer_size as _); // slower altrernative: `vec![0 as BYTE; dw_buffer_size as usize];` without
                                                                                  // set_len()
                buffer.set_len(dw_buffer_size as _);

                let p_token_user: PTOKEN_USER = std::mem::transmute_copy(&buffer);

                // Retrieve the token information in a TOKEN_USER structure
                if GetTokenInformation(
                    h_token,
                    TokenUser,
                    p_token_user as _,
                    dw_buffer_size,
                    &mut dw_buffer_size,
                ) == 1
                {
                    // Convert sid to wide string
                    let mut buffer: LPWSTR = null_mut();

                    if ConvertSidToStringSidW((*p_token_user).User.Sid, &mut buffer as _) == 1 {
                        // Get string pointed to by buffer. pointer can't be null otherwise
                        // U16CString panicks!
                        if !buffer.is_null() {
                            let sid_str = U16CString::from_ptr_str(buffer).to_string_lossy();

                            // We have what looks to be a valid sid!
                            if let Some('S') = sid_str.chars().next() {
                                sid = Ok(sid_str);
                            }
                        }
                    }

                    // Cleanup
                    LocalFree(buffer as _);
                }
            }

            // Cleanup
            CloseHandle(h_token);
        }
    }

    // TODO: implement getting sid from registry if regular method fails:
    // Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\
    // FileAssociations").GetValue("UserSid")

    sid
}

/// Obtains the executable path from
/// HKEY_CLASSES_ROOT\{app_id}\shell\open\command
fn get_executable_path_from_app_id(prog_id: &str) -> String {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);

    // Find program open shell command in registry
    let path = Path::new(prog_id).join(r"shell\open\command");
    if let Ok(key) = hkcr.open_subkey(path) {
        if let Ok(command) = key.get_value::<String, _>("") {
            return parse_open_command(&command);
        }
    }

    String::new()
}

/// Gets path to executable from a shell open command
///   Ex: `C:\aaa\chrome.exe` from `  "C:\aaa\chrome.exe" -- "%1"  `
fn parse_open_command(command: &str) -> String {
    let mut parsed = String::new();

    let mut collecting = false;
    let mut quotes = false;
    for c in command.chars() {
        if collecting {
            if quotes && c == '"' || !quotes && c.is_whitespace() {
                break;
            } else {
                parsed.push(c);
            }
        } else if c == '"' {
            collecting = true;
            quotes = true;
        } else if !c.is_whitespace() {
            collecting = true;
            parsed.push(c);
        }
    }

    parsed
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        // Always produces the same hash for same input
        assert_eq!("cCCz42ftY04=", hash_from_string("ahhhh!".to_string()));
        assert_eq!(
            "gWyVPN/cdvU=",
            hash_from_string(
                "https://github.com/rochacbruno/rust_memes/blob/master/img/ferris_thinking.jpg"
                    .to_string()
            )
        );

        // Full wide character support since we are working with utf-16
        assert_eq!(
            "WbCBu+XPckA=",
            hash_from_string("\u{1F92F}\u{1F92F}".to_string())
        );

        // Case insensitive
        assert_eq!(
            hash_from_string("ABCDEFG".to_string()),
            hash_from_string("abcdefg".to_string())
        );
    }

    #[test]
    fn test_parse_open_command() {
        // Test parsing theoretical commands
        assert_eq!(
            r"  D:\a b\browser thing .exe ",
            parse_open_command(r#" "  D:\a b\browser thing .exe " -- "%1"  "#)
        );
        assert_eq!(
            r"Z:\abc\browser.exe",
            parse_open_command(r#"   Z:\abc\browser.exe "%1" "#)
        );

        // Test parsing actual browser commands
        assert_eq!(
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            parse_open_command(
                r#""C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" -- "%1""#
            )
        );
        assert_eq!(
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            parse_open_command(
                r#""C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url "%1""#
            )
        );
        assert_eq!(
            r"C:\Program Files\Internet Explorer\iexplore.exe",
            parse_open_command(r#""C:\Program Files\Internet Explorer\iexplore.exe" %1"#)
        );
        assert_eq!(
            r"C:\Windows\system32\LaunchWinApp.exe",
            parse_open_command(r#""C:\Windows\system32\LaunchWinApp.exe" "%1""#)
        );

        // Test parsing a couple interesting commands I found in my registry
        assert_eq!(
            r"%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE",
            parse_open_command(r#""%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE" "%1""#)
        );
        assert_eq!(
            r"C:\Program Files (x86)\Notepad++\notepad++.exe",
            parse_open_command(r#""C:\Program Files (x86)\Notepad++\notepad++.exe" "%1""#)
        );
        assert_eq!(
            r"C:\Windows\system32\spool\DRIVERS\x64\3\x3fpb0N.exe",
            parse_open_command(r#"C:\Windows\system32\spool\DRIVERS\x64\3\x3fpb0N.exe -f "%1""#)
        );
        assert_eq!(
            r"C:\Windows\System32\rundll32.exe",
            parse_open_command(
                r#""C:\Windows\System32\rundll32.exe" "C:\Windows\System32\dfshim.dll",ShOpenVerbApplication %1"#
            )
        );
    }

    #[test]
    fn test_get_executable_path_from_app_id() {
        // Test Chrome
        assert_eq!(
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            get_executable_path_from_app_id("ChromeHTML")
        );

        // Test Firefox
        assert_eq!(
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            get_executable_path_from_app_id("FirefoxURL-308046B0AF4A39CB")
        );
        assert_eq!(
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            get_executable_path_from_app_id("FirefoxHTML-308046B0AF4A39CB")
        );

        // Test IE
        assert_eq!(
            r"C:\Program Files\Internet Explorer\iexplore.exe",
            get_executable_path_from_app_id("IE.HTTPS")
        );
        assert_eq!(
            r"C:\Program Files\Internet Explorer\iexplore.exe",
            get_executable_path_from_app_id("IE.HTTP")
        );
        assert_eq!(
            r"C:\Program Files\Internet Explorer\iexplore.exe",
            get_executable_path_from_app_id("IE.AssocFile.HTM")
        );

        // Test Edge
        assert_eq!(
            r"C:\Windows\system32\LaunchWinApp.exe",
            get_executable_path_from_app_id("AppX90nv6nhay5n6a98fnetv7tpk64pp35es")
        );
        assert_eq!(
            r"C:\Windows\system32\LaunchWinApp.exe",
            get_executable_path_from_app_id("AppXq0fevzme2pys62n3e0fbqa7peapykr8v")
        );
        assert_eq!(
            r"C:\Windows\system32\LaunchWinApp.exe",
            get_executable_path_from_app_id("AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9")
        );
    }

    #[test]
    fn test_get_user_sid() {
        // Pretty much the best we can do.
        // Code follows windows documentation very closely so we should be fine
        assert!(get_user_sid().is_ok());
    }

    #[test]
    fn test_get_registry_last_write_time() {
        // Pretty much the best we can do.
        // Code follows windows documentation very closely so we should be fine
        assert!(get_registry_last_write_time(&RegKey::predef(HKEY_LOCAL_MACHINE)).is_ok());
    }

    // Experimenting automatically setting VLC's default file extensions
    //  > cargo test -- --ignored --nocapture test_set_vlc_defaults
    #[test]
    #[ignore]
    pub fn test_set_vlc_defaults() {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let uc = UserPref::new(
            hkcu.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts")
                .unwrap(),
        )
        .unwrap();

        // Loop through file extensions
        // All, including a couple others found in
        // Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Clients\Media\VLC\Capabilities\
        // FileAssociations Can't use that because windows doesn't enable all of
        // vlc's defaults
        for file_ext in &[
            "3g2", "3gp2", "3gp", "3gpp", "asf", "ASX", "avi", "M1V", "m2t", "m2ts", "m4v", "mkv",
            "mov", "MP2V", "mp4", "mp4v", "mpa", "MPE", "mpeg", "mpg", "mpv2", "mts", "TS", "TTS",
        ] {
            let protocol = format!(".{}", file_ext);
            let prog_id = format!("VLC.{}", file_ext);
            uc.change(&protocol, "", &prog_id).unwrap();
        }
    }
}
