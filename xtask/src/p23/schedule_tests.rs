use std::collections::BTreeSet;

use super::manifest_tests::manifest_for;
use super::schedule::{self, Tier};
use super::target_registry;
use super::ExperimentManifest;

const PROFILES: [&str; 2] = ["lua55-i64f64", "lua54-i64f64"];

fn job_set(jobs: Vec<schedule::Job>) -> BTreeSet<(String, String, u64, u64)> {
    jobs.into_iter()
        .map(|job| {
            (
                job.target_id.to_owned(),
                job.profile.to_owned(),
                job.seed,
                job.seconds,
            )
        })
        .collect()
}

fn expected_jobs(seeds_per_pair: usize, seconds: u64) -> BTreeSet<(String, String, u64, u64)> {
    target_registry()
        .iter()
        .flat_map(|target| {
            PROFILES.iter().flat_map(move |profile| {
                (0..seeds_per_pair).map(move |extra| {
                    (
                        target.id.to_owned(),
                        (*profile).to_owned(),
                        target.seed + extra as u64 * 1_000_000,
                        seconds,
                    )
                })
            })
        })
        .collect()
}

#[test]
fn schedule_maps_targets_profiles_seeds_and_tier_budgets() {
    for (tier, release_seeds, seeds_per_pair, seconds) in [
        (Tier::PullRequest, 0, 1, 60),
        (Tier::Nightly, 0, 1, 600),
        (Tier::Release, 3, 3, 1_200),
        (Tier::Release, 4, 4, 900),
    ] {
        let jobs = schedule::schedule(tier, release_seeds).expect("有效排程應成功");
        let expected = expected_jobs(seeds_per_pair, seconds);
        assert_eq!(jobs.len(), expected.len());
        assert_eq!(job_set(jobs), expected);
    }

    assert!(schedule::schedule(Tier::Release, 0).is_err());
}

#[test]
fn release_extra_seed_is_accepted_by_manifest_validation() {
    let manifest = manifest_for("lua55-i64f64", 1_023_001);
    assert!(ExperimentManifest::parse(&manifest).is_ok());
}
