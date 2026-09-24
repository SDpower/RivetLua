# RivetLua の実装状況

[English](IMPLEMENTATION_STATUS.md) | [繁體中文](IMPLEMENTATION_STATUS.zh-TW.md) | [한국어](IMPLEMENTATION_STATUS.ko.md) | 日本語

更新日：2026-09-25。このページでは、リポジトリに実装済みの機能と今後の作業を区別します。チェック済みの項目は記載した範囲のテストに合格したことを示します。未チェックの項目はまだ実装されていません。仕様書やテスト資料が存在するだけでは、対応する実行機能が完成したことにはなりません。

## 実装・検証済み

- [x] **プロジェクトの基盤と運営文書：** Cargo ワークスペースにはコアとコンパイラのライブラリ、および検証ツールがあります。MIT または Apache-2.0 のデュアルライセンスと、貢献、セキュリティ、運営に関する文書を備えています。
- [x] **Rust のビルド基準：** 開発にはシステム既定の Rust stable ツールチェーンを使います。Cargo は最小サポート Rust バージョン（MSRV）を 1.94.1 と宣言し、ビルドとテストには `Cargo.lock` と `--locked` を使います。
- [x] **公式 Lua 参照資料：** Lua 5.5.1 と 5.4.9 それぞれの公式ソース、独立したテスト、ライセンスのスナップショットを保存し、バージョンと SHA-256 を確認します。これらは比較用であり、正式な Rust 成果物にはリンクしません。
- [x] **互換性データとテストツール：** [互換性一覧](../spec/compatibility.csv)、二つの Lua バージョン別設定、ケース実行ツール、解析可能なレポート、意図的な失敗ケースを用意しました。
- [x] **基盤の検証：** 必須ファイル、Rust バージョン、上流資料のハッシュ、実行ケース、オフラインでの再実行、正式な成果物を自動検査します。必要な検査がすべて成功した場合だけ合格とします。
- [x] **C ABI のリスク境界：** 安全な C 制御フローのケースを実行しました。リソースを保持する Rust フレームを `longjmp` で飛び越える設計は拒否します。[実験記録](../tests/abi/REPORT.md) は正式な C API の完成を意味しません。
- [x] **コアの値モデル：** Rust API は nil、真偽値、64 ビット整数、倍精度浮動小数点数、不透明なオブジェクト参照を区別します。
- [x] **数値規則：** 算術、切り下げ除算、剰余、整数のラップアラウンド、ビット演算、変換、整数と浮動小数点数の厳密な比較を一元化しました。大きな整数、NaN、符号付きゼロ、シフトの境界をテストしています。
- [x] **エラーと真偽判定：** ゼロ除算や不正なオペランドは検査可能なコアエラーを返します。偽となるのは nil と false だけで、`and` と `or` は選択したオペランドをそのまま保持します。[コア API](../crates/rivetlua-core/src/lib.rs) と外部結合テストは合格しています。
- [x] **Lua の字句解析：** [コンパイラ API](../crates/rivetlua-compiler/src/lib.rs) は Lua 5.5 と 5.4 の生バイト列からトークンを認識し、span、位置、リテラル、制限付き診断を保持します。Lua 5.5 の `global` はマニュアルに従う厳格な文法で予約語として扱います。両プロファイルの P02 ゲートが合格しています。
- [x] **Lua の構文解析：** [コンパイラ API](../crates/rivetlua-compiler/src/lib.rs) は P02 のトークンを所有権のある AST に解析し、演算子の優先順位、括弧、呼び出し、宣言、span を保持します。両プロファイルの P03 ゲートが合格しています。この段階では構文構造のみを検証します。
- [x] **Lua のスコープと名前解決：** [コンパイラ API](../crates/rivetlua-compiler/src/lib.rs) は binding、入れ子の upvalue、読み取り専用の名前、ジャンプ、クローズ経路、および Lua 5.5 の明示的な global 宣言を所有権のある解決済み AST に変換します。両プロファイルの P04 ゲートが合格しています。この段階では bytecode の生成や Lua の実行は行いません。
- [x] **中間表現と bytecode の検証：** [コンパイラ API](../crates/rivetlua-compiler/src/lib.rs) は解決済み AST を型付きレジスタ IR と RVLU_V2 bytecode に変換します。module 所有 format version、signature/vararg、ClosePath、numeric-for 専用 instruction、canonical static effects を[コア検証器](../crates/rivetlua-core/src/bytecode/codec.rs)が検査し、v1 と未知版を拒否します。両プロファイルの P05 ゲートが合格しています。これは Lua binary chunk ではありません。
- [x] **Heap、root、host handle、割り当て失敗：** [runtime crate](../crates/rivetlua-runtime/src/lib.rs) は安定したオブジェクト ID、6 種類の root、RAII host handle、割り当て計上、失敗時のロールバック、実際に回収する mark/sweep を提供します。P06 のローカル gate は 29/29 項目を通過し、各 profile で HEAP ケースを 8 件ずつ実行しました。gate は P01 と P05 も再実行します。この段階では bytecode や Lua ソースを実行しません。
- [x] **最小 VM：** runtime は検証済み RVLU_V2 module のみを受け付け、P07 対象の数値演算、local 代入、条件分岐、ループ、numeric-for、fuel 制限、終端状態を実行します。未対応 instruction と constant は明示的に拒否します。P07 のローカル gate は 30/30 項目に合格し、20 件の一意な VM ケース報告（各 profile 10 件）を生成しました。VM-005/007 は正確な入力 `while true do end` をコンパイルして検証済み module を VM に渡します。compiler codegen は関数の fallthrough 経路に暗黙の終端 `Return(Fixed(0))` を追加し、fuel 枯渇と終端状態の検査は compiler 生成 module を使います。

値、数値、字句解析、構文解析のテストは Rust API を直接呼び出します。**RivetLua は現在 P07 が対応する Lua のサブセットのみを実行し、言語全体との互換性は未検証です。**

## 今後の作業

- [ ] 文字列と raw table 操作を実装します。
- [ ] 関数、クロージャ、複数戻り値、末尾呼び出しを実装します。
- [ ] メタテーブルと関連操作を実装します。
- [ ] Lua エラー、コルーチン、クローズ対象のリソースを実装します。
- [ ] 完全なガベージコレクション、弱参照、メモリ圧迫時の処理を実装します。
- [ ] 標準ライブラリとモジュール読み込みを実装します。
- [ ] 公開 Rust SDK、モジュールのシリアライズ、コマンドラインツールを提供します。
- [ ] 公式 Lua Basic テストスイートの互換性検証に合格します。
- [ ] 正式な C API／ABI とネイティブモジュール対応を実装します。
- [ ] 公式 Lua Complete テストスイートの互換性検証に合格します。
- [ ] LuaRocks、Moonrocks、LuaUnit、Busted の利用手順を検証します。
- [ ] Lua 5.4.9 の互換性設定と回帰検査を完了します。
- [ ] 適用可能なインタプリタ最適化と JIT 対応を評価・実装します。
- [ ] AOT、複数プラットフォーム、MCU 対応を評価・実装します。
- [ ] サンドボックス、隔離プロセス、情報漏えい防止を整備します。
- [ ] ファジング、障害注入、性能検証を追加します。
- [ ] パッケージ公開、第三者による採用、1.0 リリースの検証を完了します。

## 検証を再実行する

リポジトリのルートで、システム既定の Rust stable ツールチェーンを使って実行します。

```sh
cargo fmt --all -- --check
cargo test --locked --workspace
cargo run --locked -p rivetlua-xtask -- gate P00
cargo run --locked -p rivetlua-xtask -- gate P01
cargo run --locked -p rivetlua-xtask -- gate P02
cargo run --locked -p rivetlua-xtask -- gate P03
cargo run --locked -p rivetlua-xtask -- gate P04
cargo run --locked -p rivetlua-xtask -- gate P05
cargo run --locked -p rivetlua-xtask -- gate P06
cargo run --locked -p rivetlua-xtask -- gate P07
```

`gate P00` はプロジェクトの基盤を、`gate P01` はコアの値と数値を、`gate P02` は lexer を、`gate P03` は parser を、`gate P04` はスコープと名前解決を、`gate P05` は bytecode と前段階の回帰を、`gate P06` は heap/handle 契約と P01/P05 の回帰を、`gate P07` は最小 VM と P01/P05/P06 の回帰を検査します。実行時にローカルの計画書は不要です。2026-09-22 に Rust 1.98.1 で検証した結果、書式検査とワークスペースのテストが成功し、基盤・コア・字句解析・構文解析・名前解決・bytecode の検証はそれぞれ 22/22、35/35、29/29、25/25、23/23、24/24 が合格しました。P05 には両プロファイルで各 8 ケースが含まれます。2026-09-24 の Rust 1.98.1 による P06 gate は 29/29 項目を通過しました。16 件の一意なケース報告（各 profile 8 件）、runtime unit 17 件、profile ごとの crate 外契約テスト 19 件、profile ごとに doctest 2 件（うち 1 件は compile-fail）を含みます。P07 ローカル gate は 30/30 項目に合格し、20 件の一意なケース報告（各 profile 10 件）、runtime unit 48 件、profile ごとの crate 外契約テスト 27 件を実行しました。VM-005/007 は正確な入力 `while true do end` をコンパイルして検証済み module を VM に渡し、compiler codegen は関数の fallthrough 経路に暗黙の終端 `Return(Fixed(0))` を追加します。xtask CLI では P07 のケース欠落、重複、誤った profile、破損 fixture、P01 prerequisite の失敗を検証しました。各失敗は非ゼロ終了と解析可能な FAIL JSON を出力しました。変更した fixture は `cmp -s` で復元を確認し、注入の前後で作業ツリー状態が同一でした。これはローカル検証の記録であり、リモート GitHub CI の実行を示すものではありません。レポートは `target/rivetlua-reports/` に生成され、Git に含まれず、上記のコマンドで再作成できます。Cargo が宣言する MSRV は引き続き 1.94.1 です。
