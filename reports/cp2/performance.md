# CP2 Performance Comparison

> Workload: 610 files / 5888020 bytes; 1 warm-up + 5 measured runs

| Scanner | Product | Median s | Min/max s | CV | CPU median s | Peak MiB | Throughput B/s | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| gitleaks v8.0.0-rnc.5f6ec56cfa6f | windows-amd64 | 0.786 | 0.553/1.032 | 0.196594 | 2.125 | 71.41 | 7491119.593 | STABLE |
| gitleaks v8.0.0-rnc.5f6ec56cfa6f | docker-linux-amd64 | 3.578 | 2.476/4.606 | 0.22216 | N/A | N/A | 1645617.663 | STABLE |
| gitleaks v8.0.0-rnc.5f6ec56cfa6f | docker-linux-arm64 | 6.929 | 5.726/7.445 | 0.085811 | N/A | N/A | 849764.757 | STABLE |
| betterleaks 1.8.1 | windows-amd64 | 0.683 | 0.536/0.835 | 0.173736 | 1.46875 | 113.36 | 8620819.912 | STABLE |
| betterleaks 1.8.1 | docker-linux-amd64 | 2.87 | 2.572/2.977 | 0.061318 | N/A | N/A | 2051574.913 | STABLE |
| betterleaks 1.8.1 | docker-linux-arm64 | 9.249 | 8.89/12.853 | 0.147733 | N/A | N/A | 636611.526 | STABLE |

Performance is separate from detection. Native/container and AMD64/emulated ARM64 comparisons are not directly comparable; Docker short-run CPU-seconds and peak memory are unavailable.
