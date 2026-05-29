use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gitp2p_runtime::policy::{create_policy, evaluate_policy};
use gitp2p_runtime::run_tick;
use gitp2p_testing::setup_vault_with_repo;

fn bench_policy_eval(c: &mut Criterion) {
    c.bench_function("policy_eval_and_tick_dry_run", |b| {
        let app = setup_vault_with_repo("bench-policy");
        create_policy(
            &app,
            "replica-policy",
            "replica",
            "team",
            "min_replicas=2",
        )
        .unwrap();
        b.iter(|| {
            black_box(evaluate_policy(&app, "team", None).unwrap());
            black_box(run_tick(&app, "team", true).unwrap());
        });
    });
}

criterion_group!(benches, bench_policy_eval);
criterion_main!(benches);
