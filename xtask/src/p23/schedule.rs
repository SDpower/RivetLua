use super::manifest::{MAX_RELEASE_SEEDS, release_seed, target_registry};

const PROFILES: [&str; 2] = ["lua55-i64f64", "lua54-i64f64"];
const RELEASE_SECONDS: u64 = 3600;

#[derive(Clone, Copy)]
pub(super) enum Tier {
    PullRequest,
    Nightly,
    Release,
}

pub(super) struct Job {
    pub target_id: &'static str,
    pub profile: &'static str,
    pub seed: u64,
    pub seconds: u64,
}

pub(super) fn schedule(tier: Tier, release_seeds: usize) -> Result<Vec<Job>, &'static str> {
    let (seed_count, seconds_per_seed, extra_seconds) = match tier {
        Tier::PullRequest => (1, 60, 0),
        Tier::Nightly => (1, 600, 0),
        Tier::Release => {
            if !(1..=MAX_RELEASE_SEEDS).contains(&release_seeds) {
                return Err("E_P23B04_RELEASE_SEEDS");
            }
            let count = u64::try_from(release_seeds).map_err(|_| "E_P23B04_RELEASE_SEEDS")?;
            // 每組 target/profile 預算固定 3600 秒，餘秒依序分配以維持總額。
            (
                release_seeds,
                RELEASE_SECONDS / count,
                RELEASE_SECONDS % count,
            )
        }
    };

    let mut jobs = Vec::new();
    for target in target_registry() {
        for profile in PROFILES {
            for index in 0..seed_count {
                let seed_index = u64::try_from(index).map_err(|_| "E_P23B04_SEED")?;
                let seed = release_seed(target.seed, index).ok_or("E_P23B04_SEED")?;
                jobs.push(Job {
                    target_id: target.id,
                    profile,
                    seed,
                    seconds: seconds_per_seed + if seed_index < extra_seconds { 1 } else { 0 },
                });
            }
        }
    }
    Ok(jobs)
}
