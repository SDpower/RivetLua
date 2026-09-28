# RivetLua の実装状況

[English](IMPLEMENTATION_STATUS.md) | [繁體中文](IMPLEMENTATION_STATUS.zh-TW.md) | [한국어](IMPLEMENTATION_STATUS.ko.md) | 日本語

更新日：2026-09-28。このページでは、リポジトリに実装済みの機能と今後の作業を区別します。チェック済みの項目は記載した範囲のテストに合格したことを示します。未チェックの項目はまだ実装されていません。仕様書やテスト資料が存在するだけでは、対応する実行機能が完成したことにはなりません。

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
- [x] **バイト文字列と raw table：** runtime は NUL を含む任意の byte string、array/hash raw table、canonical key、raw 読み書きと削除、byte 長、正当な table border、GC trace、割り当て失敗時のロールバックに対応します。P08 ローカル gate は 33/33 項目に合格し、TAB-001～012 の一意な報告を 24 件（各 profile 12 件）生成しました。TAB-010 は runtime 内部テストで両方の挿入順と同一の field 集合を検証します。公開 iteration library はありません。P08 では metatable と標準ライブラリを実装しません。
- [x] **関数、クロージャ、upvalue、vararg、複数戻り値、末尾呼び出し：** runtime は明示的な call frame を使い、open／closed upvalue で捕捉した local を保持し、固定引数と vararg、複数結果を調整します。Lua 5.5 の名前付き vararg table に対応し、Lua 5.4 ではその構文を拒否します。適格な末尾呼び出しでは frame を再利用し、非末尾呼び出しには深度制限があります。P09 ローカル gate は 29/29 項目に合格し、CALL-001～013 の一意な報告を 24 件生成しました。`lua55-i64f64` は CALL-001～011／013、`lua54-i64f64` は CALL-001～010／012／013 を各 12 件実行しました。CALL-013 は pending ClosePath の保持、末尾 frame の非再利用、結果数を検証し、`__close` を実際に LIFO 順で実行します。
- [x] **メタテーブルと再開可能な操作：** runtime は raw fast path、`__index`／`__newindex`、table の `__call` と operator event、制限付き event chain、P09 call frame と root を伴う PendingOp の再開に対応します。P10 ローカル gate は 26/26 項目を通過し、META-001～010 の一意な報告を 20 件（各 profile 10 件）生成しました。
- [x] **Lua エラー、coroutine、close 値：** P11 は protected boundary を越えて元の error `Value` identity を保持し、yield/resume、`coroutine.close`／`wrap`、`<close>` と generic-for closing value の LIFO cleanup に対応します。hard abort は終端の host outcome のままで、通常の Lua error や close 完了結果へ変換されません。P11 ケースに必要な VM builtin のみを導入しました。ローカル P11 gate は 366 checks で合格し、ERR-001～005、COR-001～006、CLOSE-001～005 の一意な report を 32 件（各 profile 16 件、分類別 5/6/5）生成しました。

値、数値、字句解析、構文解析のテストは Rust API を直接呼び出します。**RivetLua は現在 P11 で検証した Lua サブセットを実行し、Lua 全体との互換性は未検証です。**P11 では正式ケースに必要な VM builtin のみを導入しました。table/string 標準ライブラリと公開 `pairs`／`next` wrapper、P12 の GC 拡張と weak reference、P13 の一般標準ライブラリと module loading は今後の作業です。

## 今後の作業

- [ ] table/string 標準ライブラリ、公開 `pairs`／`next` wrapper を実装します。

- [ ] P12 の GC 拡張、weak reference、メモリ圧迫時の処理を実装します。
- [ ] P13 の一般標準ライブラリと module loading を実装します。
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
cargo test --locked --workspace -- --test-threads=1
cargo run --locked -p rivetlua-xtask -- gate P00
cargo run --locked -p rivetlua-xtask -- gate P01
cargo run --locked -p rivetlua-xtask -- gate P02
cargo run --locked -p rivetlua-xtask -- gate P03
cargo run --locked -p rivetlua-xtask -- gate P04
cargo run --locked -p rivetlua-xtask -- gate P05
cargo run --locked -p rivetlua-xtask -- gate P06
cargo run --locked -p rivetlua-xtask -- gate P07
cargo run --locked -p rivetlua-xtask -- gate P08
cargo run --locked -p rivetlua-xtask -- gate P09
cargo run --locked -p rivetlua-xtask -- gate P10
cargo run --locked -p rivetlua-xtask -- gate P11
```

`gate P00` はプロジェクトの基盤を、`gate P01` はコアの値と数値を、`gate P02` は lexer を、`gate P03` は parser を、`gate P04` はスコープと名前解決を、`gate P05` は bytecode と前段階の回帰を、`gate P06` は heap/handle 契約と P01/P05 の回帰を、`gate P07` は最小 VM と P01/P05/P06 の回帰を、`gate P08` は前段階 gate 報告と byte string/raw table の両 profile ケースを、`gate P09` は前段階報告と両 profile の CALL／関数 closure ケースを、`gate P10` は P00～P09 報告と両 profile の META ケースを検査し、`gate P11` は P00～P10 の前提報告と両 profile の ERR/COR/CLOSE ケースを検査します。実行時にローカルの計画書は不要です。2026-09-22 に Rust 1.98.1 で検証した結果、書式検査とワークスペースのテストが成功し、基盤・コア・字句解析・構文解析・名前解決・bytecode の検証はそれぞれ 22/22、35/35、29/29、25/25、23/23、24/24 が合格しました。P05 には両プロファイルで各 8 ケースが含まれます。2026-09-24 の Rust 1.98.1 による P06 gate は 29/29 項目を通過しました。16 件の一意なケース報告（各 profile 8 件）、runtime unit 17 件、profile ごとの crate 外契約テスト 19 件、profile ごとに doctest 2 件（うち 1 件は compile-fail）を含みます。P07 ローカル gate は 30/30 項目に合格し、20 件の一意なケース報告（各 profile 10 件）、runtime unit 48 件、profile ごとの crate 外契約テスト 27 件を実行しました。VM-005/007 は正確な入力 `while true do end` をコンパイルして検証済み module を VM に渡し、compiler codegen は関数の fallthrough 経路に暗黙の終端 `Return(Fixed(0))` を追加します。P08 ローカル gate は 33/33 項目に合格し、TAB-001～012 の一意な報告を 24 件（各 profile 12 件）生成しました。TAB-001～009 と TAB-011/012 は runtime contract test、TAB-010 は runtime 内部 raw traversal unit test が出力し、2 種類の挿入順を profile ごとに 1 件の報告へ統合します。CLI 負方向け検証ではケースの欠落・重複、誤った profile、破損 fixture、期待値の誤り、CSV 列や mapping の誤り、P07 報告の欠落または FAIL、test 子プロセスの失敗を扱いました。各ケースは非ゼロ終了と解析可能な FAIL JSON を確認し、fixture は `cmp -s` で復元され、作業ツリー状態も一致しました。2026-09-27 のローカル P00～P09 gate は 22/37/29/25/25/33/29/30/33/29 checks で通過し、P09 は CALL 報告 24 件（各 profile 12 件）を生成しました。workspace test と format check も合格し、xtask CLI は 18/18 でした。P09 serial CLI negative test は fixture/profile、CSV、P08 prerequisite report、失敗 child の各負ケースを実行し、FAIL JSON と byte／作業ツリー復元を確認しました。レポートは `target/rivetlua-reports/` に生成され、Git に含まれず、上記のコマンドで再作成できます。Cargo が宣言する MSRV は引き続き 1.94.1 です。
`gate P00` はプロジェクトの基盤を、`gate P01` はコアの値と数値を、`gate P02` は lexer を、`gate P03` は parser を、`gate P04` はスコープと名前解決を、`gate P05` は bytecode と前段階の回帰を、`gate P06` は heap/handle 契約と P01/P05 の回帰を、`gate P07` は最小 VM と P01/P05/P06 の回帰を、`gate P08` は前段階 gate 報告と byte string/raw table の両 profile ケースを検査します。実行時にローカルの計画書は不要です。2026-09-22 に Rust 1.98.1 で検証した結果、書式検査とワークスペースのテストが成功し、基盤・コア・字句解析・構文解析・名前解決・bytecode の検証はそれぞれ 22/22、35/35、29/29、25/25、23/23、24/24 が合格しました。P05 には両プロファイルで各 8 ケースが含まれます。2026-09-24 の Rust 1.98.1 による P06 gate は 29/29 項目を通過しました。16 件の一意なケース報告（各 profile 8 件）、runtime unit 17 件、profile ごとの crate 外契約テスト 19 件、profile ごとに doctest 2 件（うち 1 件は compile-fail）を含みます。P07 ローカル gate は 30/30 項目に合格し、20 件の一意なケース報告（各 profile 10 件）、runtime unit 48 件、profile ごとの crate 外契約テスト 27 件を実行しました。VM-005/007 は正確な入力 `while true do end` をコンパイルして検証済み module を VM に渡し、compiler codegen は関数の fallthrough 経路に暗黙の終端 `Return(Fixed(0))` を追加します。P08 ローカル gate は 33/33 項目に合格し、TAB-001～012 の一意な報告を 24 件（各 profile 12 件）生成しました。TAB-001～009 と TAB-011/012 は runtime contract test、TAB-010 は runtime 内部 raw traversal unit test が出力し、2 種類の挿入順を profile ごとに 1 件の報告へ統合します。CLI 負方向け検証ではケースの欠落・重複、誤った profile、破損 fixture、期待値の誤り、CSV 列や mapping の誤り、P07 報告の欠落または FAIL、test 子プロセスの失敗を扱いました。各ケースは非ゼロ終了と解析可能な FAIL JSON を確認し、fixture は `cmp -s` で復元され、作業ツリー状態も一致しました。

2026-09-27 のローカル検証では P00～P09 の gate がすべて通過し、aggregate checks は順に 22/37/29/25/25/33/29/30/33/29 でした。P09 は CALL 報告を 24 件（各 profile 12 件）生成しました。`cargo test --locked --workspace -- --test-threads=1` も成功し、xtask CLI は 18/18 です。format check も通過しました。P09 の serial CLI negative tests は不正 fixture／profile mapping、不正または列不足の CSV、P08 prerequisite report の欠落／FAIL／不正 JSON、失敗する child command を検証しました。各失敗で非ゼロ終了と解析可能な FAIL JSON を確認し、fixture、CSV の byte 列、作業ツリー状態を復元しました。このローカル結果は remote GitHub CI を意味しません。2026-09-28 にローカル P00～P10 gate がすべて通過し、checks は 22/37/29/25/25/33/29/30/33/29/26 でした。META 報告は 20 件（各 profile 10 件）です。workspace は exit 0（xtask unit 46/46、CLI 21/21、`p10_contracts` は各 profile 16/16）で、format check と `git diff --check` も合格しました。2026-09-28 の最終ローカル検証は合格しました。P00～P11 の gate checks は順に 22/37/29/25/25/33/29/30/33/29/26/366、P08/P09/P10/P11 の一意な PASS case report は 24/24/20/32 件でした。workspace は 26 個の test summary で 498 passed／0 failed（xtask unit 51/51、CLI 23/23、P11 contracts 48/48）です。P11 は 32 件の一意な report を生成し、各 profile 16 件（ERR/COR/CLOSE は 5/6/5）でした。隔離した clean worktree でも再構築後に P00～P11 が同じ checks で合格しました。Remote GitHub CI は未実行です。P12 の GC 拡張、P13 の一般標準ライブラリ／module loading、Lua 全体との互換性は今後の作業です。レポートは `target/rivetlua-reports/` に生成され、Git に含まれず、上記のコマンドで再作成できます。Cargo が宣言する MSRV は引き続き 1.94.1 です。


## Review 修正と再検証（2026-09-28）

- 前節の workspace 498 passed/0 failed（xtask unit 51/51、CLI 23/23、P11 contracts 48/48）は review 修正前の記録であり、本節の結果に置き換わります。動的 tail call の open 多値 producer/consumer の隣接性を保ち、引数評価後に caller の upvalue を閉じるよう修正しました。Builtin 関数を metamethod として通常の protected/coroutine 経路で呼び出せるようにしました。P00～P11 のレポートには決定的な `source_digest` を記録し、P08～P11 は runtime child を起動する前に、欠落・不正形式・古い前提レポートを拒否します。
- この文書を変更する前に、`DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --locked --workspace -- --test-threads=1` は 26 summaries で 509 passed/0 failed でした。xtask unit 52/52、CLI 24/24、P11 contracts 50/50。core 修正の検証も compiler unit 16/16、runtime unit 131/131、各 profile の P05 7/7、P09 11/11、P10 19/19、P11 50/50 で通過しました。format check と `git diff --check` も通過しました。
- 文書変更前の P00～P11 gate は順にすべて通過し、checks は 22/37/29/25/25/33/29/30/33/29/26/366。P08～P11 は一意な PASS case report を 24/24/20/32 件生成しました。その時点の 12 reports の `source_digest` は `6b94e337b2ee097266b505ea5e01f3064620f2aaa41586b0a13fdef5df2a4670` でした。この公開 status 文書も digest 対象のため、今回の編集で以前の digest は無効になります。最終レポートは確定したソースから再生成し、`source_digest` を照合する必要があります。最終検証結果は主担当の受け入れ記録を参照してください。remote GitHub CI は未実行です。P12 GC 拡張、P13 一般標準ライブラリ／module loading、完全な Lua 互換性は今後の作業です。
