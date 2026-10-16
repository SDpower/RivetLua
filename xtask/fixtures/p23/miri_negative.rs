// 僅校準手動工作能觀察失敗；不代表 Miri 已偵測未定義行為。
#[test]
fn miri_negative_control_fails() {
    assert!(false, "P23_MIRI_NEGATIVE_CONTROL");
}
