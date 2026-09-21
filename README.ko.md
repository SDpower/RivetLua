# RivetLua

[English](README.md) | [繁體中文](README.zh-TW.md) | 한국어 | [日本語](README.ja.md)

RivetLua는 다른 애플리케이션에 내장할 수 있는 순수 Rust 기반 Lua 컴파일러와 실행 엔진을 목표로 하는 독립적인 오픈 소스 프로젝트입니다.

## 현재 상태

프로젝트는 현재 기획 단계입니다. Rust SDK, 실행 엔진, 명령줄 도구는 아직 구현되지 않았으며, 호환성과 테스트 결과도 검증되지 않았습니다.

## 개발 방향

- Lua 소스 코드 또는 AST를 검증된 바이트코드로 컴파일하고 가상 머신에서 실행합니다.
- 호스트 애플리케이션을 위한 Rust SDK, 리소스 제어 및 선택적 실행 기능을 제공합니다.
- Lua 호환성을 단계별로 검증하고 적합한 플랫폼에서 JIT/AOT를 평가합니다.

## 라이선스

이 프로젝트는 이중 라이선스로 제공되며, 다음 중 하나를 선택할 수 있습니다.

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) © [@SteveLuo](https://github.com/sdpower)
