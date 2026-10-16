use rivetlua::{COMPATIBILITY_VERSION, compatibility_entries};

pub(super) fn compatibility(arguments: &[String]) -> Result<(), String> {
    let mut profile = None;
    let mut gaps = false;
    for argument in arguments {
        match argument.as_str() {
            "lua54" | "lua55" if profile.is_none() => profile = Some(argument.as_str()),
            "--gaps" if !gaps => gaps = true,
            _ => return Err("用法：compatibility [lua54|lua55] [--gaps]".into()),
        }
    }

    let entries = compatibility_entries()?;
    let entries = entries
        .iter()
        .filter(|entry| !gaps || entry.is_gap())
        .map(|entry| {
            format!(
                "{{\"area\":\"{}\",\"lua55_rule\":\"{}\",\"lua54_rule\":\"{}\",\"source\":\"{}\",\"case_id\":\"{}\",\"status\":\"{}\"}}",
                super::json_escape(entry.area),
                super::json_escape(entry.lua55_rule),
                super::json_escape(entry.lua54_rule),
                super::json_escape(entry.source),
                super::json_escape(entry.case_id),
                super::json_escape(entry.status),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let profile = profile
        .map(|profile| format!(",\"profile\":\"{profile}\""))
        .unwrap_or_default();
    println!("{{\"version\":{COMPATIBILITY_VERSION}{profile},\"entries\":[{entries}]}}");
    Ok(())
}
