use super::sha_file;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn receipt(log: &str, profile: &str) -> Result<(String, String), String> {
    let mut result = None;
    for line in log.lines().filter(|line| line.starts_with("RVP16SDK\t")) {
        if result.is_some() {
            return Err("P16 SDK receipt 重複".into());
        }
        let fields = line
            .strip_prefix("RVP16SDK\t")
            .ok_or("P16 SDK receipt 前綴無效")?
            .split('\t')
            .map(|part| part.split_once('=').ok_or("P16 SDK receipt 欄位無效"))
            .collect::<Result<Vec<_>, _>>()?;
        let expected = ["v", "profile", "result", "record_path", "record_sha256"];
        if fields.len() != expected.len()
            || fields
                .iter()
                .zip(expected)
                .any(|((key, _), want)| key != &want)
            || fields[0].1 != "1"
            || fields[1].1 != profile
            || fields[2].1 != "PASS"
            || !super::is_sha(fields[4].1)
        {
            return Err("P16 SDK receipt schema/profile/result 不符".into());
        }
        result = Some((fields[3].1.to_owned(), fields[4].1.to_owned()));
    }
    result.ok_or_else(|| "P16 SDK receipt 缺失".into())
}

pub(super) fn record_artifact(
    evidence_dir: &Path,
    receipt: &(String, String),
) -> Result<(String, String), String> {
    let path = PathBuf::from(&receipt.0);
    let canonical_dir = fs::canonicalize(evidence_dir)
        .map_err(|error| format!("P16 SDK evidence dir 不可讀：{error}"))?;
    let canonical_path =
        fs::canonicalize(&path).map_err(|error| format!("P16 SDK record 不可讀：{error}"))?;
    if !path.is_absolute()
        || !canonical_path.starts_with(&canonical_dir)
        || !canonical_path.is_file()
        || sha_file(&canonical_path)? != receipt.1
    {
        return Err("P16 SDK record 路徑或 SHA-256 不符".into());
    }
    Ok(receipt.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p16_sdk_receipt_rejects_wrong_profile_and_duplicate_success() {
        let digest = "a".repeat(64);
        let line = format!(
            "RVP16SDK\tv=1\tprofile=lua55\tresult=PASS\trecord_path=/tmp/r.json\trecord_sha256={digest}"
        );
        assert!(receipt(&line, "lua54").is_err());
        assert!(receipt(&format!("{line}\n{line}"), "lua55").is_err());
        assert_eq!(receipt(&line, "lua55").unwrap().1, digest);
        assert!(receipt(&line.replace("result=PASS", "result=NOT_RUN"), "lua55").is_err());
        let libtest = format!(
            "running 1 test\ntest sdk_modules_official_five_load_execute_and_p1 ... \n{line}\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n"
        );
        assert_eq!(receipt(&libtest, "lua55").unwrap().1, digest);
        assert!(super::super::named_libtest_passed(
            &libtest,
            "sdk_modules_official_five_load_execute_and_p1"
        ));
        assert!(receipt(&libtest.replace("\nRVP16SDK", "RVP16SDK"), "lua55").is_err());
    }

    #[test]
    fn p16_sdk_record_rejects_outside_directory_and_stale_hash() {
        let base =
            std::env::temp_dir().join(format!("rivetlua-sdk-receipt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let evidence = base.join("evidence");
        fs::create_dir_all(&evidence).unwrap();
        let inside = evidence.join("record.json");
        let outside = base.join("outside.json");
        fs::write(&inside, b"{}").unwrap();
        fs::write(&outside, b"{}").unwrap();
        let receipt = (inside.display().to_string(), sha_file(&inside).unwrap());
        assert_eq!(record_artifact(&evidence, &receipt).unwrap(), receipt);
        assert!(
            record_artifact(
                &evidence,
                &(outside.display().to_string(), sha_file(&outside).unwrap())
            )
            .is_err()
        );
        fs::write(&inside, b"{\"changed\":true}").unwrap();
        assert!(record_artifact(&evidence, &receipt).is_err());
        fs::remove_dir_all(&base).unwrap();
    }
}
