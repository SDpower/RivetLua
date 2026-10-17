use rivetlua::{COMPATIBILITY_VERSION, CompatibilityEntry, LuaProfile, compatibility_entries};

#[test]
fn sdk_exposes_profile_compatibility_queries() {
    assert_eq!(COMPATIBILITY_VERSION, 1);

    let entries: Vec<CompatibilityEntry<'static>> =
        compatibility_entries().expect("compatibility table should be readable");
    assert_eq!(entries.len(), 9);

    let keyword = entries
        .iter()
        .find(|entry| entry.case_id == "PROF-001-KEYWORD-GLOBAL")
        .expect("global keyword entry should be present");
    assert_ne!(
        keyword.selected_rule(LuaProfile::Lua55),
        keyword.selected_rule(LuaProfile::Lua54)
    );
    assert!(
        keyword
            .source
            .contains("https://www.lua.org/source/5.5/llex.c.html")
    );
    assert!(
        keyword
            .source
            .contains("https://www.lua.org/source/5.4/llex.c.html")
    );

    let unimplemented = entries
        .iter()
        .filter(|entry| entry.is_gap())
        .find(|entry| entry.case_id == "PROF-002-CAPI-OPENSELECTEDLIBS")
        .expect("open-selected-libraries entry should be present");
    assert_ne!(unimplemented.status, "implemented");
    assert!(
        unimplemented
            .source
            .contains("https://www.lua.org/source/5.5/lualib.h.html")
    );
}
