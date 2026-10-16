use super::performance::regression_requires_triage;

#[test]
fn regression_triage_uses_strict_ten_percent_threshold_and_rejects_zero() {
    assert_eq!(regression_requires_triage(100, 110), Ok(false));
    assert_eq!(regression_requires_triage(100, 111), Ok(true));
    assert_eq!(regression_requires_triage(100, 99), Ok(false));
    assert!(regression_requires_triage(0, 100).is_err());
    assert!(regression_requires_triage(100, 0).is_err());
}
