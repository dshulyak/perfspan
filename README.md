command line tool to check latency and performance counters for tracing spans
===

the tool is using usdt instrumentation integrated with rust tracing crate.
see [matmul example](./examples/matmul.rs), with a caveat that for real app you will want to add it as a layer to shared registry.

it is helpful when you want to check latency and performance counters for traces that are not collected
by your observability solution. usdt instrumentation doesn't cause any overhead when traces are not enabled,
it is good fit for adhoc debugging and performance analysis.

```sh
sudo perfspan ./target/release/examples/matmul matmul

SPAN: matmul
matmul latency: samples 100 min 62488576 max 67502079 mean 63882362.88 stdev 926286.66 p80 64585727 p95 65667071
62668µs | ***                                      |  6.0th %-ile
63170µs | **********                               | 25.0th %-ile
63671µs | ***********                              | 47.0th %-ile
64172µs | ************                             | 71.0th %-ile
64674µs | *******                                  | 84.0th %-ile
65175µs | ****                                     | 92.0th %-ile
65676µs | ***                                      | 97.0th %-ile
66178µs | *                                        | 98.0th %-ile
66679µs |                                          | 98.0th %-ile
67181µs | *                                        | 99.0th %-ile
67682µs | *
```

it also supports recording perf counters using linux perf subsystem. note that counters are sampled, for example cycles counter by default
updated on every 10 000 000 cycle, and therefore not precise. one more caveat is that thread can be interrupted and migrate to different cpu.
span may enter on one cpu and exits on another, such span will be discarded from the result.

```sh
sudo ./target/release/perfspan ./target/release/examples/matmul matmul -e cycles

SPAN: matmul
matmul cycles: samples 97 min 279969792 max 340000767 mean 322822228.45 stdev 6548404.10 p80 330039295 p95 330039295
 282145605 | *                                        |  1.0th %-ile
 288148703 |                                          |  1.0th %-ile
 294151801 |                                          |  1.0th %-ile
 300154899 |                                          |  1.0th %-ile
 306157997 |                                          |  1.0th %-ile
 312161095 |                                          |  1.0th %-ile
 318164193 |                                          |  1.0th %-ile
 324167291 | **********************************       | 68.0th %-ile
 330170389 | ****************                         | 99.0th %-ile
 336173487 |                                          | 99.0th %-ile
 342176585 | *                                        | 100.0th %-ile

```

Full list of support perf counters is available with `--help`.

## Building

Install dependencies:

```sh
sudo apt install -y build-essential autoconf clang-15 flex bison pkg-config autopoint
sudo ln -s /usr/include/asm-generic /usr/include/asm
```

Install app:

```sh
cargo install --path .
```
