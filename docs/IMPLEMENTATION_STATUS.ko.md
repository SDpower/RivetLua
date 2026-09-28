# RivetLua 구현 현황

[English](IMPLEMENTATION_STATUS.md) | [繁體中文](IMPLEMENTATION_STATUS.zh-TW.md) | 한국어 | [日本語](IMPLEMENTATION_STATUS.ja.md)

갱신일: 2026-09-29. 이 문서는 저장소에 구현된 기능과 앞으로 구현할 기능을 구분합니다. 체크된 항목은 명시된 범위의 테스트를 통과했음을 뜻합니다. 체크되지 않은 항목은 아직 구현되지 않았습니다. 사양 문서나 테스트 자료가 있다는 사실만으로 실행 기능이 완성된 것은 아닙니다.

## 구현 및 검증 완료

- [x] **프로젝트 기반과 운영 문서:** Cargo 워크스페이스에 코어 및 컴파일러 라이브러리와 검증 도구가 있습니다. MIT 또는 Apache-2.0 이중 라이선스와 기여, 보안, 운영 문서를 갖추었습니다.
- [x] **Rust 빌드 기준:** 개발에는 시스템 기본 Rust stable 도구 모음을 사용합니다. Cargo에 최소 지원 Rust 버전(MSRV) 1.94.1을 선언했고, 빌드와 테스트에는 `Cargo.lock` 및 `--locked`를 사용합니다.
- [x] **공식 Lua 참조 자료:** Lua 5.5.1과 5.4.9의 공식 소스 압축 파일, 각각의 독립 테스트 압축 파일, 라이선스 사본을 보관합니다. 버전과 SHA-256 해시를 확인합니다. 이 자료는 비교용이며 정식 Rust 산출물에 연결되지 않습니다.
- [x] **호환성 자료와 테스트 도구:** [호환성 목록](../spec/compatibility.csv), 두 Lua 버전별 설정, 사례 실행기, 파싱 가능한 보고서, 의도적인 실패 사례를 갖추었습니다.
- [x] **기반 검증:** 필수 파일, Rust 버전, 업스트림 해시, 실행기 사례, 오프라인 재실행, 정식 산출물을 자동 검사합니다. 필요한 검사가 모두 통과해야 성공으로 판정합니다.
- [x] **C ABI 위험 경계:** 안전한 C 제어 흐름 사례를 실행했습니다. 리소스를 보유한 Rust 프레임을 `longjmp`로 건너뛰는 방식은 설계상 거부합니다. [실험 기록](../tests/abi/REPORT.md)은 정식 C API가 완성되었다는 뜻이 아닙니다.
- [x] **코어 값 모델:** Rust API가 nil, 불리언, 64비트 정수, 배정밀도 부동소수점 수, 불투명한 객체 참조를 구분합니다.
- [x] **숫자 규칙:** 산술, 내림 나눗셈, 나머지, 정수 래핑, 비트 연산, 변환, 정확한 정수·부동소수점 비교를 한곳에서 처리합니다. 큰 정수, NaN, 부호 있는 0, 시프트 경계를 테스트합니다.
- [x] **오류와 참값 규칙:** 0으로 나누거나 잘못된 피연산자를 사용하면 검사 가능한 코어 오류를 반환합니다. nil과 false만 거짓이며 `and`와 `or`는 선택한 피연산자를 그대로 보존합니다. [코어 API](../crates/rivetlua-core/src/lib.rs)와 외부 통합 테스트가 통과했습니다.
- [x] **Lua 어휘 분석:** [컴파일러 API](../crates/rivetlua-compiler/src/lib.rs)는 Lua 5.5와 5.4의 원본 바이트에서 토큰을 인식하고 span, 위치, 리터럴 및 제한된 진단을 보존합니다. Lua 5.5에서는 엄격한 매뉴얼 문법에 따라 `global`을 예약어로 처리합니다. 두 프로필 모두 P02 게이트를 통과했습니다.
- [x] **Lua 구문 분석:** [컴파일러 API](../crates/rivetlua-compiler/src/lib.rs)는 P02 토큰을 소유권을 가진 AST로 파싱하고 연산자 우선순위, 괄호, 호출, 선언 및 span을 보존합니다. 두 프로필 모두 P03 게이트를 통과했습니다. 이 단계는 구문 구조만 검증합니다.
- [x] **Lua 스코프와 이름 해석:** [컴파일러 API](../crates/rivetlua-compiler/src/lib.rs)는 binding, 중첩 upvalue, 읽기 전용 이름, 점프, 닫기 경로 및 Lua 5.5의 명시적 global 선언을 소유권을 가진 해석된 AST로 변환합니다. 두 프로필 모두 P04 게이트를 통과했습니다. 이 단계에서는 bytecode를 생성하거나 Lua를 실행하지 않습니다.
- [x] **중간 표현과 bytecode 검증:** [컴파일러 API](../crates/rivetlua-compiler/src/lib.rs)는 해석된 AST를 형식이 지정된 레지스터 IR과 RVLU_V2 bytecode로 변환합니다. module 소유 format version, signature/vararg, ClosePath, numeric-for 전용 instruction, canonical static effects를 [코어 검증기](../crates/rivetlua-core/src/bytecode/codec.rs)가 검사하고 v1 및 미지 버전을 거부합니다. 두 프로필 모두 P05 게이트를 통과했습니다. 이 형식은 Lua binary chunk가 아닙니다.
- [x] **Heap, root, 호스트 handle, 할당 실패:** [runtime crate](../crates/rivetlua-runtime/src/lib.rs)는 안정적인 객체 식별, 여섯 root 종류, RAII 호스트 handle, 할당량 계정, 실패 복구 및 실제 객체를 회수하는 mark/sweep을 제공합니다. P06 로컬 게이트의 29개 검사가 통과했고 각 프로필에서 HEAP 사례 8개를 실행했습니다. 게이트는 P01과 P05도 다시 검사합니다. 이 단계는 bytecode나 Lua 소스 코드를 실행하지 않습니다.
- [x] **최소 가상 머신:** runtime은 검증된 RVLU_V2 module만 받아 P07에서 지원하는 숫자 연산, local 대입, 조건문, 반복문, numeric-for, fuel 제한, 종료 상태를 실행합니다. 지원하지 않는 instruction과 constant는 명시적으로 거부합니다. P07 로컬 게이트는 30/30 검사를 통과했고 VM 사례 보고서 20개(프로필별 10개)를 만들었습니다. VM-005/007은 정확한 입력 `while true do end`를 컴파일하고 검증된 module을 VM에 전달합니다. compiler codegen은 함수가 끝까지 실행되는 경로에 암시적 마지막 `Return(Fixed(0))`을 추가하며, fuel 고갈과 terminal-state 검사는 compiler가 생성한 module을 사용합니다.
- [x] **바이트 문자열과 raw table:** runtime은 NUL을 포함한 임의 바이트 문자열, array/hash raw table, canonical key, raw 읽기/쓰기/삭제, 바이트 길이, 유효한 table 경계, GC trace 및 할당 실패 롤백을 지원합니다. P08 로컬 게이트는 33/33 검사를 통과했고 TAB-001～012 고유 보고서 24개(프로필별 12개)를 만들었습니다. TAB-010은 runtime 내부 테스트에서 두 삽입 순서와 동일한 필드 집합을 확인합니다. 공개 iteration library는 제공하지 않습니다. P08은 metatable과 표준 라이브러리를 구현하지 않습니다.
- [x] **함수, 클로저, upvalue, vararg, 다중 반환, 꼬리 호출:** runtime은 명시적 call frame을 사용하고 open/closed upvalue로 캡처한 local을 보존하며 고정 매개변수와 vararg, 다중 결과를 조정합니다. Lua 5.5의 이름 있는 vararg table을 지원하고 Lua 5.4에서는 해당 문법을 거부합니다. 가능한 꼬리 호출에서 frame을 재사용하고 비꼬리 호출 깊이를 제한합니다. P09 로컬 게이트는 29/29 검사를 통과하고 CALL-001～013 고유 보고서 24개를 만들었습니다. `lua55-i64f64`는 CALL-001～011/013, `lua54-i64f64`는 CALL-001～010/012/013을 각각 12개씩 실행했습니다. CALL-013은 pending ClosePath 보존, 꼬리 frame 미재사용, 결과 수와 실제 LIFO `__close` 실행을 검증합니다.
- [x] **메타테이블과 재개 가능한 작업:** runtime은 raw fast path, `__index`／`__newindex`, table의 `__call`과 operator event, 제한된 event chain, P09 call frame과 root를 보유한 PendingOp 재개를 지원합니다. P10 로컬 gate는 26/26 검사를 통과했고 META-001～010 고유 보고서 20개(프로필별 10개)를 만들었습니다.
- [x] **Lua 오류, coroutine, 닫기 값:** P11은 보호 경계를 넘어 원래 오류 `Value`의 identity를 보존하고 yield/resume, `coroutine.close`/`wrap`, `<close>`와 generic-for closing value의 LIFO 정리를 지원합니다. hard abort는 terminal host 결과이며 일반 Lua 오류나 정상 close 결과로 바뀌지 않습니다. P11 사례에 필요한 VM builtin만 설치했습니다. 로컬 P11 gate는 366 checks를 통과했고 ERR-001～005, COR-001～006, CLOSE-001～005 고유 보고서 32개(프로필별 16개, 분류별 5/6/5)를 만들었습니다.

값, 숫자, 어휘 및 구문 테스트는 Rust API를 직접 호출합니다. **RivetLua는 현재 P11에서 검증한 Lua 하위 집합을 실행하며, Lua 전체 호환성은 아직 검증되지 않았습니다.** P11 정식 사례에 필요한 VM builtin만 설치했습니다. table/string 표준 라이브러리와 공개 `pairs`/`next` wrapper, P12 GC 확장과 약한 참조, P13 일반 표준 라이브러리와 모듈 로딩은 후속 작업입니다.

## 남은 작업

- [ ] table/string 표준 라이브러리와 공개 `pairs`/`next` wrapper를 구현합니다.

- [ ] P12 GC 확장, 약한 참조, 메모리 압박 처리를 구현합니다.
- [ ] P13 일반 표준 라이브러리와 모듈 로딩을 구현합니다.
- [ ] 공개 Rust SDK, 모듈 직렬화, 명령줄 도구를 제공합니다.
- [ ] 공식 Lua Basic 테스트 모음의 호환성 검증을 통과합니다.
- [ ] 정식 C API/ABI와 네이티브 모듈 지원을 구현합니다.
- [ ] 공식 Lua Complete 테스트 모음의 호환성 검증을 통과합니다.
- [ ] LuaRocks, Moonrocks, LuaUnit, Busted 사용 흐름을 검증합니다.
- [ ] Lua 5.4.9 호환 설정과 회귀 검사를 완료합니다.
- [ ] 적용 가능한 인터프리터 최적화와 JIT 지원을 평가하고 구현합니다.
- [ ] AOT, 교차 플랫폼, MCU 지원을 평가하고 구현합니다.
- [ ] 샌드박스, 격리 프로세스, 정보 유출 방지 기능을 만듭니다.
- [ ] 퍼징, 장애 주입, 성능 검증을 추가합니다.
- [ ] 패키지 공개, 제삼자 사용, 1.0 릴리스 검증을 완료합니다.

## 검증 다시 실행하기

저장소 루트에서 시스템 기본 Rust stable 도구 모음으로 실행합니다.

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

`gate P00`은 프로젝트 기반을, `gate P01`은 코어 값과 숫자를, `gate P02`는 lexer를, `gate P03`는 parser를, `gate P04`는 스코프와 이름 해석을, `gate P05`는 bytecode와 앞 단계 회귀를, `gate P06`은 heap/handle 계약과 P01/P05 회귀를, `gate P07`은 최소 VM과 P01/P05/P06 회귀를, `gate P08`은 앞 단계 gate 보고서와 두 프로필의 byte string/raw table 사례를, `gate P09`는 선행 보고서와 두 프로필의 CALL 및 함수/closure 사례를, `gate P10`은 P00～P09 보고서와 두 프로필의 META 사례를 검사하고, `gate P11`은 P00～P10 선행 보고서와 두 프로필의 ERR/COR/CLOSE 사례를 검사합니다. 실행에 로컬 계획 문서는 필요하지 않습니다. 2026-09-22에 Rust 1.98.1로 확인한 결과, 서식 검사와 워크스페이스 테스트가 통과했고 기반·코어·어휘·구문·이름 해석·bytecode 검증은 각각 22/22, 35/35, 29/29, 25/25, 23/23, 24/24 항목이 통과했습니다. P05에는 각 프로필의 사례 8개가 포함됩니다. 2026-09-24 Rust 1.98.1 P06 게이트는 29/29 검사를 통과했습니다. 여기에는 16개의 고유 사례 보고서(프로필별 8개), runtime unit 17개, 프로필별 crate 외부 계약 테스트 19개, 그리고 프로필별 doctest 2개(그중 compile-fail 1개)가 포함됩니다. P07 로컬 게이트는 30/30 검사를 통과했고 사례 보고서 20개(프로필별 10개), runtime unit 48개, 프로필별 외부 계약 테스트 27개를 실행했습니다. VM-005/007은 정확한 입력 `while true do end`를 컴파일하고 검증된 module을 VM에 전달합니다. compiler codegen은 함수의 fallthrough 경로에 암시적 마지막 `Return(Fixed(0))`을 추가합니다. xtask CLI에서 P07 사례 누락·중복·잘못된 profile·손상된 fixture·실패한 P01 prerequisite를 검증했습니다. 각 실패는 0이 아닌 종료 코드와 파싱 가능한 FAIL JSON을 만들었습니다. 변경 fixture는 `cmp -s`로 복원을 확인했고 주입 전후 작업 디렉터리 상태도 동일했습니다. P08 로컬 gate는 33/33 검사를 통과하고 TAB-001～012 고유 보고서 24개(프로필별 12개)를 만들었습니다. TAB-001～009와 TAB-011/012는 runtime contract test, TAB-010은 runtime 내부 raw traversal unit test에서 생성되며 두 삽입 순서를 프로필별 하나의 보고서로 합칩니다. CLI 부정 테스트는 사례 누락/중복, 잘못된 profile, 손상 fixture, expected 오류, CSV 누락 열/mapping 오류, P07 보고서 누락/FAIL, test 하위 프로세스 실패를 검증했습니다. 각 실패에서 비정상 종료와 파싱 가능한 FAIL JSON을 확인했으며 fixture와 작업 디렉터리 상태를 복원했습니다. 2026-09-27 로컬 P00～P09 게이트는 모두 통과했고 검사는 22/37/29/25/25/33/29/30/33/29였습니다. P09는 CALL 보고서 24개(프로필별 12개)를 만들었습니다. workspace 테스트와 format check가 통과했고 xtask CLI는 18/18이었습니다. P09 serial CLI 부정 테스트는 fixture/profile mapping, CSV, P08 prerequisite report, 실패 child를 확인했으며 각 실패에서 FAIL JSON과 fixture／CSV／작업 트리 복원을 검증했습니다. 보고서는 `target/rivetlua-reports/`에 생성되며 Git에 포함되지 않고 위 명령으로 다시 만들 수 있습니다. Cargo에 선언된 MSRV는 여전히 1.94.1입니다.

P08 로컬 gate는 33/33 검사를 통과했고 TAB-001～012 고유 보고서 24개(프로필별 12개)를 생성했습니다. TAB-001～009 및 TAB-011/012는 runtime contract test, TAB-010은 runtime 내부 raw traversal unit test에서 나오며 두 삽입 순서를 프로필별 한 보고서로 합칩니다. CLI 부정 테스트는 사례 누락/중복, 잘못된 profile, 손상 fixture, expected 오류, CSV 누락 열/잘못된 mapping, P07 보고서 누락/FAIL, test 하위 프로세스 실패를 검증했습니다. 각 경우 비정상 종료와 파싱 가능한 FAIL JSON을 확인했으며 fixture는 `cmp -s`로 복원되고 작업 디렉터리 상태도 유지됐습니다. 이는 로컬 결과이며 원격 GitHub CI 실행을 의미하지 않습니다.

`gate P08`은 선행 gate 보고서와 두 profile의 byte string/raw table 사례를, `gate P09`는 선행 보고서와 두 profile의 CALL 사례 및 함수/closure 동작을 검증합니다. 2026-09-27 로컬 검증에서 P00～P09 게이트가 모두 통과했고 aggregate 검사는 순서대로 22/37/29/25/25/33/29/30/33/29였습니다. P09는 고유 CALL 보고서 24개(프로필별 12개)를 만들었습니다. `cargo test --locked --workspace -- --test-threads=1`도 통과했고 xtask CLI는 18/18이며 format check도 통과했습니다. P09 serial CLI 부정 테스트는 잘못된 fixture/profile mapping, 손상되거나 열이 빠진 CSV, P08 prerequisite report 누락/FAIL/잘못된 JSON, 실패하는 child command를 확인했습니다. 각 실패는 0이 아닌 종료와 파싱 가능한 FAIL JSON을 만들었고 fixture, CSV 바이트, 작업 트리 상태를 복구했습니다. 이는 로컬 검증이며 원격 GitHub CI 실행을 의미하지 않습니다. 2026-09-28 로컬 P00～P10 게이트가 모두 통과했고 검사는 22/37/29/25/25/33/29/30/33/29/26이었습니다. META 보고서 20개(프로필별 10개)를 만들었습니다. workspace는 exit 0(xtask unit 46/46, CLI 21/21, `p10_contracts` 각 프로필 16/16)이며 format check와 `git diff --check`도 통과했습니다. 2026-09-28 최종 로컬 검증을 통과했습니다. P00～P11 gate checks는 순서대로 22/37/29/25/25/33/29/30/33/29/26/366이고, P08/P09/P10/P11 고유 PASS 사례 보고서는 24/24/20/32개입니다. workspace는 26개 test summary에서 498 passed/0 failed였으며 xtask unit 51/51, CLI 23/23, P11 contracts 48/48입니다. P11은 고유 보고서 32개를 만들었고 프로필별 16개(ERR/COR/CLOSE는 5/6/5)입니다. 격리된 clean worktree에서도 새로 빌드해 P00～P11을 같은 checks로 통과했습니다. 이는 2026-09-28 로컬 검증 당시의 과거 상태이며, 이후 원격 CI 결과는 아래에 기록했습니다. P12 GC 확장, P13 일반 표준 라이브러리/모듈 로딩, Lua 전체 호환성은 후속 작업입니다.


## Review 수정 및 재검증 (2026-09-28)

- 앞 절의 workspace 498 passed/0 failed(xtask unit 51/51, CLI 23/23, P11 contracts 48/48)는 review 수정 전 기록이며 이 결과로 대체됩니다. 동적 tail call의 open 다중 결과 producer와 consumer 인접성을 유지하고 인수 평가 후 caller upvalue를 닫도록 수정했습니다. Builtin 함수를 metamethod로 지정해도 일반 protected/coroutine 경로로 호출합니다. P00～P11 보고서에 결정적 `source_digest`를 기록하고, P08～P11은 runtime child를 시작하기 전에 누락·잘못된 형식·오래된 선행 증거를 거부합니다.
- 문서 편집 전 `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --locked --workspace -- --test-threads=1` 결과는 26개 요약, 509 passed/0 failed였습니다. xtask unit 52/52, CLI 24/24, P11 contracts 50/50이며, core 수정 검증은 compiler unit 16/16, runtime unit 131/131, 각 profile의 P05 7/7, P09 11/11, P10 19/19, P11 50/50이었습니다. format check와 `git diff --check`도 통과했습니다.
- 문서 편집 전 P00～P11 gate가 순서대로 모두 통과했고 checks는 22/37/29/25/25/33/29/30/33/29/26/366이었습니다. P08～P11은 고유 PASS case report 24/24/20/32개를 생성했습니다. 당시 12개 보고서의 `source_digest`는 `6b94e337b2ee097266b505ea5e01f3064620f2aaa41586b0a13fdef5df2a4670`였습니다. 공개 상태 문서도 digest 대상이므로 이번 편집으로 기존 digest는 무효가 됩니다. 최종 보고서는 확정된 소스에서 다시 생성하고 `source_digest` 값을 대조해야 합니다. 최종 검증 결과는 주 에이전트의 인수 검증 기록을 기준으로 합니다. 이는 2026-09-28 로컬 검증 당시의 과거 상태이며, 이후 원격 CI 결과는 아래에 기록했습니다. P12 GC 확장, P13 일반 표준 라이브러리/모듈 로딩, 전체 Lua 호환성은 후속 작업입니다.

## GitHub Actions 최종 검증 (2026-09-29)

- [GitHub Actions run 36444257299](https://github.com/SDpower/RivetLua/actions/runs/36444257299)은 commit `badd790cb2d3839c7c105fc1ed084bb859e2818e`에서 성공했습니다. 세 matrix 작업(macOS 15 aarch64, Ubuntu 24.04 x86_64, Ubuntu 24.04 ARM aarch64) 모두 formatting, `cargo test --locked --workspace`, P00～P11 12개 gate 단계 및 gate report artifact 업로드에 성공했고, 각 작업에 report artifact가 있습니다.
- P08 TAB 24/24, P09 CALL 24/24, P10 META 20/20, P11 ERR/COR/CLOSE 32/32 사례가 통과했습니다.
- 위의 원격 CI 미실행 기록은 2026-09-28 로컬 검증 시점의 과거 기록이며 이 절의 후속 결과로 갱신됩니다. 이 절에 기록된 문서 수정은 commit `badd790`의 CI 이후에 이루어져 해당 검증에 포함되지 않았습니다. 공개 상태 문서도 `source_digest`에 포함되므로 해당 CI의 digest를 이후 수정의 증거로 사용할 수 없습니다. 수정된 소스 상태의 digest는 별도로 생성하고 대조해야 합니다.
- P12 GC 확장, P13 일반 표준 라이브러리와 모듈 로딩, Lua 전체 호환성은 아직 완료되지 않았습니다.
