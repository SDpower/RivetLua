use rivetlua::{Engine, LuaProfile};

fn main() {
    let module = Engine::new(LuaProfile::Lua55)
        .compile(b"return 1")
        .expect("公開 API 可建立 fixture module");
    let _ = module.verified;
}
