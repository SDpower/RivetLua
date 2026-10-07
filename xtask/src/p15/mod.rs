mod gate;
mod manifest;
mod parser;
mod result;
mod runner;

pub(super) fn official_tests(args: &[String]) -> Result<(), String> {
    runner::official_tests(args)
}

pub(super) fn gate() -> Result<(), String> {
    gate::gate()
}

#[cfg(test)]
mod tests {
    use super::{manifest, parser};

    #[test]
    fn p15_manifest_exact_profiles_and_source_integrity() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        for profile in ["lua55-i64f64", "lua54-i64f64"] {
            let source = manifest::source(root, profile).unwrap();
            assert!(source.tarball_sha256.len() == 64);
            assert!(source.all_lua_sha256.len() == 64);
            assert!(manifest::verify_archive(root, &source).is_ok());
        }
        assert!(manifest::source(root, "lua54").is_err());
    }

    #[test]
    fn p15_parser_rejects_final_ok_after_prior_error() {
        let case = parser::parse(
            b"Starting Tests\nassertion failed\nfinal OK !!!\n",
            b"",
            Some(0),
        );
        assert!(case.final_ok);
        assert_eq!(case.assertion_count, 1);
        assert!(!case.provisional_pass);
        let case = parser::parse(
            b"Starting Tests\nfinal OK !!!\n",
            b"PANIC: crashed\n",
            Some(0),
        );
        assert!(case.final_ok);
        assert_eq!(case.panic_count, 1);
        assert!(!case.provisional_pass);
        assert!(!parser::parse(b"final OK !!!\n", b"", Some(9)).provisional_pass);
        assert!(!parser::parse(b"", b"", Some(0)).provisional_pass);
        let case = parser::parse(
            b"Starting Tests\nnot performed: db\nfinal OK !!!\n",
            b"",
            Some(0),
        );
        assert_eq!(case.skip_messages.len(), 1);
        assert!(!case.provisional_pass);
        let case = parser::parse(
            b"Starting Tests\nfinal OK !!!\n",
            b"Segmentation fault\n",
            Some(0),
        );
        assert_eq!(case.crash_count, 1);
        assert!(!case.provisional_pass);
    }

    #[test]
    fn p15_entire_source_tree_must_match_verified_archive() {
        use std::fs;
        use std::process::Command;
        let real = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let scratch =
            std::env::temp_dir().join(format!("rivetlua-p15-tree-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(scratch.join("tests/p15")).unwrap();
        fs::create_dir_all(scratch.join("vendor/lua55")).unwrap();
        fs::copy(
            real.join("tests/p15/runner-manifest.toml"),
            scratch.join("tests/p15/runner-manifest.toml"),
        )
        .unwrap();
        fs::copy(
            real.join("vendor/lua55/tests.tar.gz"),
            scratch.join("vendor/lua55/tests.tar.gz"),
        )
        .unwrap();
        assert!(
            Command::new("tar")
                .arg("-xzf")
                .arg(scratch.join("vendor/lua55/tests.tar.gz"))
                .arg("-C")
                .arg(scratch.join("vendor/lua55"))
                .status()
                .unwrap()
                .success()
        );
        let source = manifest::source(&scratch, "lua55-i64f64").unwrap();
        let untouched = manifest::prepare(&scratch, &source, &scratch.join("work-valid")).unwrap();
        assert_eq!(untouched.1.len(), 42);
        assert_eq!(
            untouched.2,
            "5432d9cbcbd02e2ba545d4ebf0fb7b0da76737161385fd7742af1cc94a114a04"
        );
        let source54 = manifest::source(real, "lua54-i64f64").unwrap();
        let exact54 = manifest::prepare(real, &source54, &scratch.join("work-54")).unwrap();
        assert_eq!(exact54.1.len(), 41);
        assert_eq!(
            exact54.2,
            "5db46ca54dc1659f40937700cab42bb198eb74ee1c3d113b6c19f35672ef6649"
        );
        fs::write(
            scratch.join("vendor/lua55/lua-5.5.1-tests/bitwise.lua"),
            b"altered",
        )
        .unwrap();
        assert!(manifest::prepare(&scratch, &source, &scratch.join("work-mutated")).is_err());
        let _ = fs::remove_dir_all(&scratch);
    }
}
