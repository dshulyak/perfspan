How to use?
===

```sh
sudo ./target/release/perfspan ./target/release/examples/matmul matmul

matmul: samples 100 min 61833216 max 67502079 mean 63130664.96 stdev 1332253.34 p90 64913407 p99 65798143
62357µs | *********************                    | 51.0th %-ile
62924µs | ****                                     | 59.0th %-ile
63491µs | ****                                     | 68.0th %-ile
64058µs |                                          | 68.0th %-ile
64625µs | ***                                      | 75.0th %-ile
65191µs | *********                                | 97.0th %-ile
65758µs | *                                        | 98.0th %-ile
66325µs | *                                        | 99.0th %-ile
66892µs |                                          | 99.0th %-ile
67459µs | *                                        | 100.0th %-ile
```

First argument is a binary with usdt probes from lib. After binary follows variadnic number of spans
that will be traced, each span will be printed as a separate histogram.
