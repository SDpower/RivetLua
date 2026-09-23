# RivetLua 구현 현황

[English](IMPLEMENTATION_STATUS.md) | [繁體中文](IMPLEMENTATION_STATUS.zh-TW.md) | 한국어 | [日本語](IMPLEMENTATION_STATUS.ja.md)

갱신일: 2026-09-22. 이 문서는 저장소에 구현된 기능과 앞으로 구현할 기능을 구분합니다. 체크된 항목은 명시된 범위의 테스트를 통과했음을 뜻합니다. 체크되지 않은 항목은 아직 구현되지 않았습니다. 사양 문서나 테스트 자료가 있다는 사실만으로 실행 기능이 완성된 것은 아닙니다.

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
- [x] **중간 표현과 bytecode 검증:** [컴파일러 API](../crates/rivetlua-compiler/src/lib.rs)는 해석된 AST를 형식이 지정된 레지스터 IR과 RVLU_V2 bytecode로 변환합니다. module 소유 format version, signature/vararg, ClosePath, numeric-for 전용 instruction, canonical static effects를 [코어 검증기](../crates/rivetlua-core/src/bytecode/codec.rs)가 검사하고 v1 및 미지 버전을 거부합니다. 두 프로필 모두 P05 게이트를 통과했습니다. 이 형식은 Lua binary chunk가 아니며 Lua를 실행하지 않습니다. P06+는 `NOT_IMPLEMENTED` 상태입니다.

값, 숫자, 어휘 및 구문 테스트는 Rust API를 직접 호출합니다. **RivetLua는 아직 Lua 소스 코드를 실행할 수 없으며, 완전한 Lua 언어 호환성도 검증되지 않았습니다.**

## 남은 작업

- [ ] 힙 객체, 루트, 핸들, 메모리 할당 실패를 관리합니다.
- [ ] 제어 흐름과 대입을 실행하는 최소 가상 머신을 만듭니다.
- [ ] 문자열과 원시 테이블 연산을 구현합니다.
- [ ] 함수, 클로저, 다중 반환, 꼬리 호출을 구현합니다.
- [ ] 메타테이블과 관련 연산을 구현합니다.
- [ ] Lua 오류, 코루틴, 닫아야 하는 리소스를 구현합니다.
- [ ] 전체 가비지 컬렉션, 약한 참조, 메모리 압박 처리를 구현합니다.
- [ ] 표준 라이브러리와 모듈 로딩을 구현합니다.
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
cargo test --locked --workspace
cargo run --locked -p rivetlua-xtask -- gate P00
cargo run --locked -p rivetlua-xtask -- gate P01
cargo run --locked -p rivetlua-xtask -- gate P02
cargo run --locked -p rivetlua-xtask -- gate P03
cargo run --locked -p rivetlua-xtask -- gate P04
cargo run --locked -p rivetlua-xtask -- gate P05
```

`gate P00`은 프로젝트 기반을, `gate P01`은 코어 값과 숫자를, `gate P02`는 lexer를, `gate P03`은 parser를, `gate P04`는 스코프와 이름 해석을, `gate P05`는 bytecode와 앞 단계 회귀를 검사합니다. 실행에 로컬 계획 문서는 필요하지 않습니다. 2026-09-22에 Rust 1.98.1로 확인한 결과, 서식 검사와 워크스페이스 테스트가 통과했고 기반·코어·어휘·구문·이름 해석·bytecode 검증은 각각 22/22, 35/35, 29/29, 25/25, 23/23, 24/24 항목이 통과했습니다. P05에는 각 프로필의 사례 8개가 포함됩니다. 보고서는 `target/rivetlua-reports/`에 생성되며, 이 디렉터리는 Git에 포함되지 않고 위 명령으로 다시 만들 수 있습니다. Cargo에 선언된 MSRV는 여전히 1.94.1입니다.
