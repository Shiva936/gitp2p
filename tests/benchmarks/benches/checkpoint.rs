use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gitp2p_core::create_checkpoint;
use gitp2p_testing::setup_vault_with_repo;

fn bench_checkpoint(c: &mut Criterion) {
    c.bench_function("create_checkpoint", |b| {
        b.iter(|| {
            let app = setup_vault_with_repo("bench-cp");
            let repo = app.all_repos().unwrap().pop().unwrap();
            black_box(create_checkpoint(&app, Some(&repo.id), false, false, false).unwrap());
        });
    });
}

criterion_group!(benches, bench_checkpoint);
criterion_main!(benches);
