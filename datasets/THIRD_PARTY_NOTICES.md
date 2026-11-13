# Third-party notices

The scan harness fetches the corpora below into ignored local caches. No corpus
fixture content is committed to this repository. This file preserves the required
attribution and license notices.

## Gitleaks pinned functional fixtures

- **Source:** <https://github.com/RNC-Solutions-Group/gitleaks>
- **Pinned revision:** `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c`
- **Upstream project:** <https://github.com/gitleaks/gitleaks>
- **License:** MIT
- **License file:** <https://github.com/RNC-Solutions-Group/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/LICENSE>
- **License SHA-256:** `e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6`
- **Contents:** the pinned `testdata/` tree and related Git metadata, acquired
  only into a separate revision-addressed cache for acceptance testing.

### MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Leaky Repo

- **Source:** <https://github.com/Plazmaz/leaky-repo>
- **Pinned revision:** `2e951359cac53addbee56437da3ffb546e3dfe24`
- **License:** MIT
- **License file:** <https://github.com/Plazmaz/leaky-repo/blob/2e951359cac53addbee56437da3ffb546e3dfe24/LICENSE>
- **License SHA-256 (Git blob):** `fcba3a10b27145467a3c92560a806e09ede71977584e4627b5a33f2e42cdf66f`
- **Scoring inventory:** `datasets/leaky-repo.inventory.json` — 44 file rows, 96 risk count units, 79 informative count units, 175 total.
- **Inventory SHA-256:** `146df5e25fa987a0b5c5610a958941e5416a29c9f72eadaa3677abc620b281ce`
- **Contents:** deliberately leaky, synthetic example repository used as a
  count-based filesystem benchmark. The source worktree is acquired only into an
  ignored cache and is never committed.

### MIT License

Copyright (c) 2019 Dylan Katz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Levain FP Corpus

- **Source:** <https://github.com/levainbot/fp-corpus>
- **Pinned revision:** `c130c321aa9046af17a6c876cb97e2ed71397110` (tag `v1`, 2026-09-10)
- **Author:** Levain (an autonomous AI agent) — <https://levain.bmac.io>
- **License:** MIT
- **License file:** <https://github.com/levainbot/fp-corpus/blob/c130c321aa9046af17a6c876cb97e2ed71397110/LICENSE>
- **Corpus contents:** synthetic positive and negative fixtures; every planted
  credential is synthetic, generated from a fixed seed, and has never been live.
- **License SHA-256:** `77cc69213a9c08cbd96f731793cff881a4b40a1d0682c70c70a1846afc700043`

### MIT License

Copyright (c) 2026 Levain (an autonomous AI agent) — https://levain.bmac.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Betterleaks

- **Source:** <https://github.com/betterleaks/betterleaks>
- **Pinned revision:** `5eab48332cc48565864514e3bc6de89df091a7c4` (release `v1.8.1`)
- **License:** MIT (Copyright (c) 2026 Zachary Rice)
- **License file:** <https://github.com/betterleaks/betterleaks/blob/main/LICENSE>
- **Windows binary SHA-256:** `727820f1a9f9264319cc50458b99f01acbb93e93df7a39b8eaa2715a7b1aaed5`
- **Windows archive SHA-256:** `94310d028285a1bcce7f160bc19eb62f87de6460c95bfd4319151ef5b501ed3f`
- **Docker AMD64 image:** `ghcr.io/betterleaks/betterleaks:v1.8.1`
- **Docker ARM64 digest:** `sha256:12175773aede5b775478f8eb04dffc64ed1f6c29b8f3fd61851bcf2757d1e874`
- **Use:** second independent production scanner benchmarked on synthetic and pinned benchmark data; no credential validation or analysis is enabled.

### MIT License

Copyright (c) 2026 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
