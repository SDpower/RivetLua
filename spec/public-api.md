# 公開 API 契約草案

未來介面包含 `Compiler.compile`、`Compiler.compile_ast`、`Vm.load`、`Vm.call`、`Vm.resume` 與 `ModuleCodec.encode`／`decode`。它們的 module 必須已驗證，不能提供任意 bytecode 建構入口。

未來執行狀態為 `Returned`、`Yielded`、`LuaError` 與 `Aborted`；多重回傳與 VM 身分 handle 必須保留。P00 未提供上述 API 的實作。
