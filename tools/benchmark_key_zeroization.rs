//! Isolated buffer-lifetime probe; not a production encryption implementation.
//! Compile with rustc -O --edition=2024 and --extern zeroize=<built rlib>.
//! Measures allocation + initialization + Drop zeroization + deallocation.
//! Does not measure RSA object cleanup, all backend copies, or process memory.
use std::hint::black_box;
use std::time::Instant;
use zeroize::Zeroizing;

fn main() {
    let count = 200_000;
    println!("{{\"scope\":\"Rust buffer lifecycle, zeroize 1.9.1, optimized, wall time only\",\"results\":[");
    for (index, size) in [32, 96, 2048].into_iter().enumerate() {
        let mut batches = Vec::new();
        for _ in 0..5 {
            let start = Instant::now();
            for _ in 0..count {
                let secret = Zeroizing::new(vec![0xa5_u8; size]);
                black_box(secret.as_slice());
                drop(secret);
            }
            batches.push(start.elapsed().as_nanos() as f64 / count as f64);
        }
        batches.sort_by(f64::total_cmp);
        let comma = if index == 0 { "" } else { "," };
        println!("{comma}{{\"bytes\":{size},\"median_wall_ns\":{:.3},\"batch_mean_range_ns\":[{:.3},{:.3}],\"operations_per_batch\":{count},\"batches\":5}}",
                 batches[2], batches[0], batches[4]);
    }
    println!("]}}");
}
