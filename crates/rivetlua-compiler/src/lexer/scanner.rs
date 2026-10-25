use rivetlua_core::Number;
use super::{NumericBudget, NumericCharge};

pub(crate) enum NumberError<E> {
    Syntax(&'static str),
    Budget(E),
}

impl<E> From<&'static str> for NumberError<E> {
    fn from(value: &'static str) -> Self {
        Self::Syntax(value)
    }
}

// 這僅辨識 Rust 1.98.1 Decimal::try_fast_path 必定接受的普通分支；
// 其餘所有形式保守計入完整 f64 慢路徑。掃描已讀取的 token bytes，
// 不計算浮點值，也不配置或更動 scanner 的接受語法。
fn decimal_native_fast_subset(bytes: &[u8]) -> bool {
    let exponent_at = bytes
        .iter()
        .position(|byte| matches!(byte, b'e' | b'E'))
        .unwrap_or(bytes.len());
    let (significand, exponent_with_marker) = bytes.split_at(exponent_at);
    let mut digits = 0usize;
    let mut mantissa = 0u64;
    let mut fractional_digits = 0i32;
    let mut fractional = false;
    for &byte in significand {
        if byte == b'.' {
            fractional = true;
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
        let Some(next_digits) = digits.checked_add(1) else {
            return false;
        };
        if next_digits > 19 {
            return false;
        }
        digits = next_digits;
        let Some(next_mantissa) = mantissa
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
        else {
            return false;
        };
        mantissa = next_mantissa;
        if fractional {
            let Some(next_fractional_digits) = fractional_digits.checked_add(1) else {
                return false;
            };
            fractional_digits = next_fractional_digits;
        }
    }
    if digits == 0 || mantissa > (1u64 << 53) {
        return false;
    }
    let mut explicit_exponent = 0i32;
    if !exponent_with_marker.is_empty() {
        let mut exponent = &exponent_with_marker[1..];
        let negative = exponent.first() == Some(&b'-');
        if matches!(exponent.first(), Some(b'-' | b'+')) {
            exponent = &exponent[1..];
        }
        if exponent.is_empty() {
            return false;
        }
        for &byte in exponent {
            if !byte.is_ascii_digit() {
                return false;
            }
            let digit = i32::from(byte - b'0');
            let next = if negative {
                explicit_exponent
                    .checked_mul(10)
                    .and_then(|value| value.checked_sub(digit))
            } else {
                explicit_exponent
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(digit))
            };
            let Some(next) = next else {
                return false;
            };
            explicit_exponent = next;
        }
    }
    let Some(effective_exponent) = explicit_exponent.checked_sub(fractional_digits) else {
        return false;
    };
    (-22..=22).contains(&effective_exponent)
}

pub(crate) fn parse_number<B: NumericBudget>(
    bytes: &[u8],
    budget: &mut B,
) -> Result<Number, NumberError<B::Error>> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| NumberError::Syntax("numeral 不是 ASCII"))?;
    let hexadecimal = text.starts_with("0x") || text.starts_with("0X");
    if hexadecimal {
        let body = &text[2..];
        let float_form = body.contains(['.', 'p', 'P']);
        if !float_form {
            let mut value = 0u64;
            for byte in body.bytes() {
                let digit = u64::from(hex_value(byte).ok_or("十六進位 numeral 不合法")?);
                value = value.wrapping_mul(16).wrapping_add(digit);
            }
            return Ok(Number::Integer(value as i64));
        }
        let (mantissa, mut exponent) = match body.find(['p', 'P']) {
            Some(index) => {
                let mut exponent = body[index + 1..].as_bytes();
                let negative = exponent.first() == Some(&b'-');
                if matches!(exponent.first(), Some(b'-' | b'+')) {
                    exponent = &exponent[1..];
                }
                if exponent.is_empty() {
                    return Err(NumberError::Syntax("十六進位 exponent 不合法"));
                }
                let mut magnitude = 0i128;
                for &byte in exponent {
                    if !byte.is_ascii_digit() {
                        return Err(NumberError::Syntax("十六進位 exponent 不合法"));
                    }
                    magnitude = magnitude
                        .saturating_mul(10)
                        .saturating_add(i128::from(byte - b'0'));
                }
                (&body[..index], if negative { -magnitude } else { magnitude })
            }
            None => (body, 0),
        };
        let mut value = 0u128;
        let mut fractional = false;
        let mut significant_digits = 0usize;
        let mut discarded_nonzero = false;
        for byte in mantissa.bytes() {
            if byte == b'.' {
                if fractional {
                    return Err(NumberError::Syntax("十六進位小數點不合法"));
                }
                fractional = true;
                continue;
            }
            let digit = hex_value(byte).ok_or("十六進位 numeral 不合法")?;
            if significant_digits == 0 && digit == 0 {
                if fractional {
                    exponent = exponent.saturating_sub(4);
                }
            } else if significant_digits < 30 {
                value = (value << 4) | u128::from(digit);
                significant_digits += 1;
                if fractional {
                    exponent = exponent.saturating_sub(4);
                }
            } else {
                discarded_nonzero |= digit != 0;
                if !fractional {
                    exponent = exponent.saturating_add(4);
                }
            }
        }
        budget
            .before_conversion(NumericCharge::HexPowi)
            .map_err(NumberError::Budget)?;
        return Ok(Number::Float(scale_hex_float(value, exponent, discarded_nonzero)));
    }
    if text.contains(['.', 'e', 'E']) {
        let charge = if decimal_native_fast_subset(bytes) {
            NumericCharge::DecimalFast(bytes.len())
        } else {
            NumericCharge::DecimalConservative(bytes.len())
        };
        budget
            .before_conversion(charge)
            .map_err(NumberError::Budget)?;
        let value = text.parse::<f64>().map_err(|_| "浮點 numeral 不合法")?;
        return Ok(Number::Float(value));
    }
    match text.parse::<i64>() {
        Ok(value) => Ok(Number::Integer(value)),
        Err(_) => {
            budget
                .before_conversion(NumericCharge::DecimalConservative(bytes.len()))
                .map_err(NumberError::Budget)?;
            let value = text.parse::<f64>().map_err(|_| "整數 numeral 不合法")?;
            Ok(Number::Float(value))
        }
    }
}

fn scale_hex_float(value: u128, exponent: i128, discarded_nonzero: bool) -> f64 {
    if value == 0 {
        return 0.0;
    }
    let mut binary_exponent = exponent.saturating_add(i128::from(127 - value.leading_zeros()));
    if binary_exponent > 1023 {
        return f64::INFINITY;
    }
    if binary_exponent < -1075 {
        return 0.0;
    }
    let unit_exponent = if binary_exponent < -1022 {
        -1074
    } else {
        binary_exponent - 52
    };
    // 30 個有效十六進位位數與上面的指數界限，保證右移量不超過 120 位。
    let shift = unit_exponent - exponent;
    let mut rounded = if shift > 0 {
        let shift = shift as u32;
        let truncated = value >> shift;
        let remainder = value & ((1u128 << shift) - 1);
        let halfway = 1u128 << (shift - 1);
        let round_up = remainder > halfway
            || (remainder == halfway && (discarded_nonzero || truncated & 1 != 0));
        truncated + u128::from(round_up)
    } else {
        value << ((-shift) as u32)
    };
    if binary_exponent < -1022 {
        return f64::from_bits(rounded as u64);
    }
    if rounded == 1u128 << 53 {
        rounded >>= 1;
        binary_exponent += 1;
        if binary_exponent > 1023 {
            return f64::INFINITY;
        }
    }
    let bits = ((binary_exponent + 1023) as u64) << 52
        | ((rounded as u64) & ((1u64 << 52) - 1));
    f64::from_bits(bits)
}



fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
