# 公開 API 契約草案

未來介面包含 `Compiler.compile`、`Compiler.compile_ast`、`Vm.load`、`Vm.call`、`Vm.resume` 與 `ModuleCodec.encode`／`decode`。它們的 module 必須已驗證，不能提供任意 bytecode 建構入口。

公開 bytecode API 提供只能由 decode/verify 建立的 immutable `VerifiedModule`，並可讀取 `format_version()` 與 `profile()`；RVLU_V2 另公開封閉 `InstructionEffects` static contract。這些 API 不執行 Lua。未來執行狀態為 `Returned`、`Yielded`、`LuaError` 與 `Aborted`；多重回傳與 VM 身分 handle 必須保留，仍屬 P06+ `NOT_IMPLEMENTED`。
