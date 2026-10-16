use rivetlua::{Engine, LuaProfile};

fn main() {
    let _ = Engine::new(LuaProfile::Lua55).compile(b"return 1");
}
