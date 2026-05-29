use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gitp2p_content::{cas_root, store_chunk};
use gitp2p_testing::setup_vault_with_repo;

fn bench_cas_store(c: &mut Criterion) {
    c.bench_function("cas_store_chunk", |b| {
        let app = setup_vault_with_repo("bench-cas");
        let data = vec![0u8; 4096];
        b.iter(|| {
            black_box(store_chunk(&cas_root(&app.home), black_box(&data)).unwrap());
        });
    });
}

criterion_group!(benches, bench_cas_store);
criterion_main!(benches);
