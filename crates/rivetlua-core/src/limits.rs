//! P01 固定數值配置。

/// RivetLua P01 整數使用的位元數。
pub const INTEGER_BITS: u32 = 64;

/// P01 測試與報告使用的固定數值配置名稱。
pub const NUMBER_CONFIGURATION: &str = "i64f64";

/// P01 整數最小值。
pub const INTEGER_MIN: i64 = i64::MIN;

/// P01 整數最大值。
pub const INTEGER_MAX: i64 = i64::MAX;

#[cfg(test)]
mod tests {
    use super::{INTEGER_BITS, INTEGER_MAX, INTEGER_MIN, NUMBER_CONFIGURATION};

    #[test]
    fn configuration_is_fixed_to_i64_and_f64() {
        assert_eq!(INTEGER_BITS, 64);
        assert_eq!(NUMBER_CONFIGURATION, "i64f64");
        assert_eq!(INTEGER_MIN, i64::MIN);
        assert_eq!(INTEGER_MAX, i64::MAX);
    }
}
