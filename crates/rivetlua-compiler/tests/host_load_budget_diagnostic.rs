use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, Literal, Token,
    compile_with_budget, lex, lower, parse, resolve,
};
use rivetlua_core::{VerifyLimits, verified_module_allocation_bytes};

#[derive(Clone, Copy, Debug)]
enum Charge {
    Work(usize),
    Temporary(usize),
    Module(usize),
}

#[derive(Default)]
struct RecordingSink {
    charges: Vec<Charge>,
}

impl CompileBudgetSink for RecordingSink {
    type Error = ();

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.charges.push(Charge::Work(units));
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.charges.push(Charge::Temporary(bytes));
        Ok(())
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.charges.push(Charge::Module(bytes));
        Ok(())
    }
}

fn diagnostic_case(name: &str, chunk_name: &[u8], source: &[u8], profile: LanguageProfile) {
    let mut sink = RecordingSink::default();
    let result = compile_with_budget(
        source,
        chunk_name,
        profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut sink,
    );
    let mut work = 0usize;
    let mut temporary = 0usize;
    let mut retained = 0usize;
    let first_temporary = sink
        .charges
        .iter()
        .position(|charge| matches!(charge, Charge::Temporary(_)))
        .expect("完整編譯應有 LEX temporary 申報");
    let second_temporary = sink
        .charges
        .iter()
        .enumerate()
        .skip(first_temporary + 1)
        .find_map(|(index, charge)| matches!(charge, Charge::Temporary(_)).then_some(index))
        .expect("完整編譯應有 parse temporary 申報");
    let parse_work = second_temporary - 1;
    let mut numeric_work = 0usize;
    let mut numeric_claims = 0usize;
    for (index, charge) in sink.charges.iter().enumerate() {
        match charge {
            Charge::Work(value) => {
                work += value;
                if (first_temporary + 1..parse_work).contains(&index) {
                    numeric_work += value;
                    numeric_claims += 1;
                }
            }
            Charge::Temporary(value) => temporary += value,
            Charge::Module(value) => retained += value,
        }
        eprintln!(
            "case={name} profile={profile:?} charge#{index} {charge:?} numeric_lex={} cumulative_work={work} cumulative_temp={temporary} cumulative_module={retained}",
            (first_temporary + 1..parse_work).contains(&index)
        );
    }
    match result {
        Ok(module) => {
            let actual_retained = verified_module_allocation_bytes(&module).unwrap();
            let limits = CompileLimits::default();
            let lexed = lex(source, profile, &limits).unwrap();
            let lexed_dynamic = lexed.tokens.capacity() * core::mem::size_of::<Token>()
                + lexed
                    .tokens
                    .iter()
                    .filter_map(|token| token.literal.as_ref())
                    .map(|literal| match literal {
                        Literal::Name(bytes) | Literal::String(bytes) => bytes.capacity(),
                        Literal::Integer(_) | Literal::Float(_) => 0,
                    })
                    .sum::<usize>();
            let ast = parse(&lexed, profile, &limits).unwrap();
            let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let bindings: usize = resolved.functions.iter().map(|f| f.bindings.len()).sum();
            let instructions: usize = ir.prototypes.iter().map(|p| p.instructions.len()).sum();
            let constants: usize = ir.prototypes.iter().map(|p| p.constants.len()).sum();
            eprintln!(
                "case={name} profile={profile:?} actual_shape tokens={} token_capacity={} lexed_dynamic={lexed_dynamic} root_statements={} functions={} bindings={bindings} prototypes={} instructions={instructions} constants={constants}",
                lexed.tokens.len(),
                lexed.tokens.capacity(),
                ast.root.statements.len(),
                resolved.functions.len(),
                ir.prototypes.len(),
            );
            eprintln!(
                "case={name} profile={profile:?} source_bytes={} total_work={work} numeric_work={numeric_work} numeric_claims={numeric_claims} total_temp={temporary} total_module={retained} actual_retained={actual_retained}",
                source.len()
            );
            assert!(actual_retained <= retained);
        }
        Err(error) => panic!(
            "case={name} profile={profile:?} source_bytes={} compile error: {error:?}",
            source.len()
        ),
    }
}

#[test]
#[ignore = "需明示 RIVETLUA_HOSTLOAD_MAIN 指向 RAW v10 唯讀 fixture"]
fn record_host_load_source_compile_claims() {
    let main_path = std::env::var_os("RIVETLUA_HOSTLOAD_MAIN")
        .expect("須以 RIVETLUA_HOSTLOAD_MAIN 指定本次唯讀官方 main.lua");
    let main_raw = std::fs::read(main_path).unwrap();
    assert_eq!(main_raw.len(), 16146);
    // loadfile() 先以單一換行取代首行 # 註解，編譯的是此正規化來源。
    let end = main_raw.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let mut main = vec![b'\n'];
    main.extend_from_slice(&main_raw[end..]);
    eprintln!(
        "official-main.lua raw_bytes={} normalized_bytes={}",
        main_raw.len(),
        main.len()
    );
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        diagnostic_case("decimal-fast", b"=decimal-fast", b"return 1.25", profile);
        diagnostic_case(
            "decimal-conservative",
            b"=decimal-conservative",
            b"return 9007199254740993e0",
            profile,
        );
        diagnostic_case("hex-powi", b"=hex-powi", b"return 0x1.8", profile);
        diagnostic_case(
            "five-blocks",
            b"@code.lua",
            &b"do local x=1 end\n".repeat(5),
            profile,
        );
        diagnostic_case(
            "twenty-one-blocks",
            b"@code.lua",
            &b"do local x=1 end\n".repeat(21),
            profile,
        );
    }
    diagnostic_case(
        "official-main.lua",
        b"@main.lua",
        &main,
        LanguageProfile::Lua55,
    );
}
