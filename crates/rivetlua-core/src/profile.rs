//! 語言 profile 的已實作語意能力。

use crate::LuaProfile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileRules {
    pub global_declarations: bool,
    pub named_vararg: bool,
    pub readonly_for_control: bool,
    pub table_create: bool,
}

const LUA55_RULES: ProfileRules = ProfileRules {
    global_declarations: true,
    named_vararg: true,
    readonly_for_control: true,
    table_create: true,
};

const LUA54_RULES: ProfileRules = ProfileRules {
    global_declarations: false,
    named_vararg: false,
    readonly_for_control: false,
    table_create: false,
};

impl LuaProfile {
    pub const fn rules(self) -> ProfileRules {
        match self {
            Self::Lua55 => LUA55_RULES,
            Self::Lua54 => LUA54_RULES,
        }
    }
}
