use core::cmp::Ordering;
use core::ffi::CStr;
#[cfg(feature = "std")]
use core::ffi::{c_char, c_int};

#[cfg(feature = "std")]
#[repr(C)]
struct LocaleConvPrefix {
    decimal_point: *const c_char,
}

#[cfg(feature = "std")]
unsafe extern "C" {
    #[link_name = "isalnum"]
    fn c_isalnum(byte: c_int) -> c_int;
    #[link_name = "isalpha"]
    fn c_isalpha(byte: c_int) -> c_int;
    #[link_name = "iscntrl"]
    fn c_iscntrl(byte: c_int) -> c_int;
    #[link_name = "isdigit"]
    fn c_isdigit(byte: c_int) -> c_int;
    #[link_name = "isgraph"]
    fn c_isgraph(byte: c_int) -> c_int;
    #[link_name = "islower"]
    fn c_islower(byte: c_int) -> c_int;
    #[link_name = "ispunct"]
    fn c_ispunct(byte: c_int) -> c_int;
    #[link_name = "isspace"]
    fn c_isspace(byte: c_int) -> c_int;
    #[link_name = "isupper"]
    fn c_isupper(byte: c_int) -> c_int;
    #[link_name = "isxdigit"]
    fn c_isxdigit(byte: c_int) -> c_int;
    #[link_name = "localeconv"]
    fn c_localeconv() -> *const LocaleConvPrefix;
    #[link_name = "strcoll"]
    fn c_strcoll(left: *const c_char, right: *const c_char) -> c_int;
    #[link_name = "tolower"]
    fn c_tolower(byte: c_int) -> c_int;
    #[link_name = "toupper"]
    fn c_toupper(byte: c_int) -> c_int;
}

pub fn strcoll(left: &CStr, right: &CStr) -> Ordering {
    #[cfg(feature = "std")]
    {
        // SAFETY：CStr 保證兩個借用指標於呼叫期間有效且以 NUL 結尾。
        unsafe { c_strcoll(left.as_ptr(), right.as_ptr()).cmp(&0) }
    }
    #[cfg(not(feature = "std"))]
    {
        left.to_bytes().cmp(right.to_bytes())
    }
}

#[doc(hidden)]
pub fn classify(byte: u8, class: u8) -> Option<bool> {
    #[cfg(feature = "std")]
    {
        let byte = c_int::from(byte);
        // SAFETY：byte 轉成 c_int 後必在 C ctype 函式接受的 unsigned char 範圍。
        let result = unsafe {
            match class {
                b'a' => c_isalpha(byte),
                b'c' => c_iscntrl(byte),
                b'd' => c_isdigit(byte),
                b'g' => c_isgraph(byte),
                b'l' => c_islower(byte),
                b'p' => c_ispunct(byte),
                b's' => c_isspace(byte),
                b'u' => c_isupper(byte),
                b'w' => c_isalnum(byte),
                b'x' => c_isxdigit(byte),
                _ => return None,
            }
        };
        Some(result != 0)
    }
    #[cfg(not(feature = "std"))]
    {
        Some(match class {
            b'a' => byte.is_ascii_alphabetic(),
            b'c' => byte.is_ascii_control(),
            b'd' => byte.is_ascii_digit(),
            b'g' => byte.is_ascii_graphic(),
            b'l' => byte.is_ascii_lowercase(),
            b'p' => byte.is_ascii_punctuation(),
            b's' => matches!(byte, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' '),
            b'u' => byte.is_ascii_uppercase(),
            b'w' => byte.is_ascii_alphanumeric(),
            b'x' => byte.is_ascii_hexdigit(),
            _ => return None,
        })
    }
}

#[doc(hidden)]
pub fn decimal_point() -> u8 {
    #[cfg(feature = "std")]
    {
        // SAFETY：C localeconv 回傳有效的 lconv，首欄為 NUL 結尾 decimal_point 字串。
        let decimal_point = unsafe { (*c_localeconv()).decimal_point };
        // SAFETY：localeconv 所回傳的 decimal_point 至少含一個可讀 byte（可能是 NUL）。
        unsafe { *decimal_point.cast::<u8>() }
    }
    #[cfg(not(feature = "std"))]
    {
        b'.'
    }
}

pub fn lower(byte: u8) -> u8 {
    #[cfg(feature = "std")]
    {
        // SAFETY：byte 轉成 c_int 後必在 C ctype 函式接受的 unsigned char 範圍。
        unsafe { c_tolower(c_int::from(byte)) as u8 }
    }
    #[cfg(not(feature = "std"))]
    {
        byte.to_ascii_lowercase()
    }
}

pub fn upper(byte: u8) -> u8 {
    #[cfg(feature = "std")]
    {
        // SAFETY：byte 轉成 c_int 後必在 C ctype 函式接受的 unsigned char 範圍。
        unsafe { c_toupper(c_int::from(byte)) as u8 }
    }
    #[cfg(not(feature = "std"))]
    {
        byte.to_ascii_uppercase()
    }
}


