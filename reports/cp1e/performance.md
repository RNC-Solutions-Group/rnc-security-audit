# CP1E Performance Benchmark

> Dataset: `leaky-repo` (610 files, 5888020 bytes)
> Workload: `leaky-repo-filesystem-replicated-x10`

| Product | Median s | Min s | Max s | CPU s | Peak MiB | Throughput B/s | Stability |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| windows-amd64 | 0.675 | 0.617 | 0.823 | 2.09375 | 72.83 | 8722992.593 | STABLE |
| docker-linux-amd64 | 2.129 | 1.878 | 2.401 | N/A | N/A | 2765627.055 | STABLE |
| docker-linux-arm64 | 5.377 | 4.985 | 7.286 | N/A | N/A | 1095038.125 | STABLE |

Performance is separate from detection correctness. ARM64 Docker is emulated on the AMD64 host and is not directly comparable to native AMD64.
Short container runs can finish before `docker stats` produces a sample; unavailable CPU/memory values are reported as unavailable, not zero.
