use std::time::Duration;

use tracing::instrument;

fn main() {
    tracing_perfspan::init();

    loop {
        anything();
    }
}

#[instrument]
fn anything() {
    // spin for 10ms
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(10) {}
}
