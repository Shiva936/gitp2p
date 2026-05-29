use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gitp2p_content::merkle_root;

fn bench_merkle_root(c: &mut Criterion) {
    let leaves: Vec<String> = (0..64).map(|i| format!("leaf-{i}")).collect();
    let refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    c.bench_function("merkle_root_64_leaves", |b| {
        b.iter(|| black_box(merkle_root(black_box(&refs))));
    });
}

criterion_group!(benches, bench_merkle_root);
criterion_main!(benches);
