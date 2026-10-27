# Embedded system CA bundle

NerdQAxe pins curl's Mozilla-derived bundle from October 20, 2026 (118 roots).

Ported from [bitaxeorg/ESP-Miner PR #2040](https://github.com/bitaxeorg/ESP-Miner/pull/2040), commit `d212a0f948cb3ffd90c7ca9572e9b2cf2d865d80`, by skot and mutatrum. The certificate snapshot, checksum, and incident archive are copied unchanged. The build configuration and CI integration target this NerdQAxe lineage's ESP-IDF 5.3.3 (builder 0.0.1), not upstream's 6.0.2.

Bundle provenance:

- Source: https://curl.se/ca/cacert-2026-10-20.pem
- Published checksum: https://curl.se/ca/cacert-2026-10-20.pem.sha256
- SHA-256: `796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe`
- License: [Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/), as documented by [curl](https://curl.se/docs/caextract.html).

The [eMudhra incident](https://emudhra.we-have-a-problem.com/) compromised intermediate CA keys. This snapshot removes `emSign ECC Root CA - G3` and excludes `AAA Certificate Services`, blocking the eMudhra and Sectigo cross-signed paths. Root removal also prevents connections to legitimate servers whose only trust path uses those roots. Pool operators must serve a chain to a remaining trusted root.

`sdkconfig.defaults` disables ESP-IDF's full, common, and deprecated lists and enables only this custom bundle. ESP-IDF custom bundles are otherwise **additive**. Do not re-enable the default or deprecated lists: ESP-IDF v5.3.3 includes affected roots in its bundled certificates. CMake rejects configurations that would bypass these settings, including existing `sdkconfig` files that override the defaults.

For an existing checkout, edit the certificate-bundle and trusted-callback entries in `sdkconfig` to match `sdkconfig.defaults`. Alternatively, back up `sdkconfig`, remove it, and let `idf.py reconfigure` regenerate it from `sdkconfig.defaults` (reapply any other local settings). The build guard also runs during configuration, so update the file before running `idf.py menuconfig`. Use a clean build when changing trust stores.

The exact 118 real DER roots are embedded in `esp-miner.bin`; the unused compact bundle payload is not linked. Deployed miners need a firmware OTA update. Updating the build host's trust store does not update devices. Stratum's **TLS (System certificate)** mode uses this bundle. **TLS (Custom certificate)** continues to use the configured certificate and needs separate review if that certificate trusts an affected chain. NerdQAxe also attaches this system bundle in the factory OTA downloader (`main/http_server/handler_ota_factory.cpp`), external API requests (`main/tasks/apis_task.cpp`), and Discord notifications (`main/discord.cpp`). Those HTTPS consumers inherit the same root removals; check their endpoints before release.

## Verification

Run the offline regression check with Python 3 and OpenSSL 3:

```sh
python3 tools/test_ca_bundle.py
```

It checks the bundle checksum, the root count, absence of the two affected trust anchors, an accepted ISRG Root X1 control, and rejection of all 12 published incident chains for an untrusted issuer. It disables certificate time checks so that expired fixtures cannot make this security check pass accidentally (the firmware's default mbedTLS configuration also disables expiry checks). OpenSSL's system trust directories and store are excluded.

The test archive is an unmodified copy of https://emudhra.we-have-a-problem.com/chains.zip captured on October 20, 2026. Its SHA-256 is `8a2edc81b6c51e3ad27d45ca1e441ec84c961e2dee0fc547f2a02c0f74315f95`. Its embedded README describes the chains. It contains public certificates, no private keys. All 12 chains were accepted by ESP-IDF v5.3.3 and v5.3.6's original full `cacrt_all.pem` trust stores with certificate time checks disabled; the replacement rejects them. The full default store alone is enough to reproduce the vulnerability on both NerdQAxe SDK versions.

After building with the ESP-IDF environment sourced, verify compact generation policy, exact real-DER embedding, and absence of the unused compact payload:

```sh
python tools/test_ca_bundle.py --build-dir build
```

Host verification does not replace an on-device TLS handshake test. Before release, test both primary and fallback pools, confirm a connection to an unaffected pool in system-certificate mode, and confirm TLS rejection of the incident test hosts (including `dv-g3b-emudhra.we-have-a-problem.com` and `dv-g3b-aaa-emudhra.we-have-a-problem.com`). Review any configured custom CA separately.

For future bundle updates, download a dated snapshot and its published checksum, verify them, update the filename and settings in `sdkconfig.defaults` and `CMakeLists.txt`, update the checksum and expected root count in the test, and rerun the checks before building and distributing firmware. Builds never download a mutable CA bundle.


## Bounded native root lookup

ESP-IDF's compact bundle callback in these pinned SDKs can reject a complete
server chain containing a redundant cross-signed root, even when the approved
self-signed root is available. OpenSSL acceptance of that chain does not prove
that the compact SDK callback accepts it. The four system-certificate consumers
use `real_roots_attach`: Discord, external APIs, the factory downloader, and
system pool TLS. Explicit custom-certificate pool configuration remains separate.

The helper supplies full approved DER roots through the native trusted-CA
callback. Its first-CN comparison is an overinclusive allocation prefilter, not
authentication. Native mbedTLS still checks the complete name, signature, CA
usage, constraints, hostname, and configured time policy. The helper does not
clear verification flags, add a trust anchor, fetch a certificate, or weaken a
custom-certificate path. Attaching it replaces the old compact-bundle verify
hook on reused configurations; it is not a general replacement for custom
verification callbacks or global certificate stores.

Only immutable input bytes are shared. Parsed roots are allocated per lookup,
transferred to mbedTLS only after every candidate parses, and freed by the
native verifier. Failed partial lists are unwound with the same allocator.
For this exact frozen set, lookup is bounded to seven candidates and 6,969 DER
input bytes, including three roots without CN. The complete DER payload is
127,103 bytes in flash. These are not total TLS heap or stack budgets.

Regenerate and check the deterministic input with:

```sh
python3 tools/generate_real_roots.py
python3 tools/generate_real_roots.py --check
```

CMake rejects stale callback/bundle configuration and modified generated input.
The offline certificate checks run without the build; the existing post-build
CI invocation additionally checks `esp-idf/mbedtls/x509_crt_bundle` against a
fresh SDK conversion, all 118 exact DER certificates in the application, and
absence of the unused compact payload.

The SDK versions remain unchanged. Firmware expiry checking remains disabled
by the inherited configuration; hostname and signature checking are not
bypassed. Host verifier and Linux-preview SDK transport tests do not establish
ESP heap availability, PSRAM allocation success, task-stack headroom, or
on-device acceptance. Application-only builds do not authorize installation,
factory updates, or any device operation.


### Native all-root ownership regression

With CMake, a C compiler, and the unchanged release SDK available, run:

```sh
python3 tools/native_ca_selection.py --idf-path "$IDF_PATH" --build-dir build-ca-native
```

This separate host build parses and selects every approved root, checks the
overinclusive equivalent-name prefilter, fails every reached allocation index,
and requires complete ownership cleanup. It builds only a host executable;
it neither builds nor flashes firmware. The generated data and helper are the
same files compiled by the application. The name-equivalence seam is not a
newly signed noncanonical certificate fixture. This focused selection test is
not a claim of complete socket-handshake fault coverage.
