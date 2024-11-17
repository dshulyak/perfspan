use std::hint::black_box;

use clap::Parser;
use eyre::Result;

use perfspan::PerfspanSubscriber;
use tracing::{instrument, level_filters::LevelFilter};
use tracing_subscriber::{prelude::*, Registry};

#[derive(Parser)]
struct Opt {
    #[clap(short, long, help = "size of the matrix", default_value_t = 400)]
    size: usize,
    #[clap(short, long, help = "number of iterations", default_value_t = 100)]
    iterations: usize,
}

fn main() -> Result<()> {
    let registry = Registry::default().with(
        PerfspanSubscriber {}.with_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        ),
    );
    tracing::dispatcher::set_global_default(registry.into())
        .expect("failed to set global default subscriber");

    let opt = Opt::parse();
    let mut matrix_a = vec![vec![0.0; opt.size]; opt.size];
    let mut matrix_b = vec![vec![0.0; opt.size]; opt.size];
    // randomize both matrices
    for i in 0..opt.size {
        for j in 0..opt.size {
            matrix_a[i][j] = rand::random();
            matrix_b[i][j] = rand::random();
        }
    }
    for _ in 0..opt.iterations {
        black_box(matmul(&matrix_a, &matrix_b, opt.size));
    }
    Ok(())
}

#[allow(clippy::needless_range_loop)]
#[instrument]
fn matmul(a: &[Vec<f64>], b: &[Vec<f64>], size: usize) -> Vec<Vec<f64>> {
    let mut c = vec![vec![0.0; size]; size];
    for i in 0..size {
        for k in 0..size {
            for j in 0..size {
                c[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    c
}
