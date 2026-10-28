#!/usr/bin/env python3
"""Run offline all-root selection and fault tests with the lineage's pinned SDK.

Uses a separate native mbedTLS build, never modifies SDK sources or devices.
"""
import argparse
import os
from pathlib import Path
import subprocess
import shlex
import hashlib
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PINNED = "6db3dc25df7325c1c81b7cd7d4e42babff7a818e"
MBEDTLS_PIN = "98fcfd6d2cea90d306e8fde8e5bffd6087c9cda8"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idf-path", type=Path, default=os.environ.get("IDF_PATH"), required=not os.environ.get("IDF_PATH"))
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    sdk = args.idf_path.resolve()
    build = args.build_dir.resolve()
    sha = subprocess.check_output(["git", "-C", str(sdk), "rev-parse", "HEAD"], text=True).strip()
    if sha != PINNED:
        raise SystemExit("Use the unchanged lineage SDK 5.3.6 or 5.3.3")
    subprocess.run(["git", "-C", str(sdk), "diff", "--exit-code", "HEAD", "--", "components/mbedtls"], check=True)
    subprocess.run([os.sys.executable, str(ROOT / "tools/generate_real_roots.py"), "--check"], check=True)
    source = sdk / "components/mbedtls/mbedtls"
    if subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() != MBEDTLS_PIN:
        raise SystemExit("Wrong mbedTLS submodule")
    subprocess.run(["git", "-C", str(source), "diff", "--exit-code", "HEAD"], check=True)
    build.mkdir(parents=True, exist_ok=False)
    flags = ['-DMBEDTLS_PLATFORM_MEMORY', '-DMBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK', '-DMBEDTLS_CONFIG_FILE="native_ca_config.h"', '-I' + str(ROOT / 'tools')]
    if os.uname().sysname == "Darwin":
        flags += ["-Wno-error=unterminated-string-initialization", "-Wno-error=uninitialized-const-pointer"]
    subprocess.run(["cmake", "-S", str(source), "-B", str(build), "-DENABLE_TESTING=OFF", "-DENABLE_PROGRAMS=OFF", "-DCMAKE_C_FLAGS=" + shlex.join(flags)], check=True)
    subprocess.run(["cmake", "--build", str(build), "--parallel", "4"], check=True)
    executable = build / "ca-selection"
    libs = [str(build / "library" / ("lib" + name + ".a")) for name in ["mbedtls", "mbedx509", "mbedcrypto"]]
    subprocess.run([os.environ.get("CC", "cc"), "-O2", *flags, "-I" + str(source / "include"), "-I" + str(ROOT / "main"), str(ROOT / "tools/native_ca_selection.c"), str(ROOT / "main/real_roots.c"), *libs, "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
    fixtures = ROOT / "certificates/test/native"
    for name, digest in json.loads((fixtures / "SHA256SUMS.json").read_text()).items():
        assert hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == digest, name
    def compile_probe(name):
        exe = build / name
        subprocess.run([os.environ.get("CC", "cc"), "-O2", "-pthread", "-DMBEDTLS_ALLOW_PRIVATE_ACCESS", *flags, "-I" + str(source / "include"), "-I" + str(ROOT / "main"), str(ROOT / "tools" / (name + ".c")), str(ROOT / "main/real_roots.c"), *libs, "-o", str(exe)], check=True)
        return exe
    verifier = compile_probe("native_ca_verify")
    negative = compile_probe("native_ca_negative")
    def verify(chain, host, expected, bit=0):
        result = subprocess.run([str(verifier), str(chain), host, "0", "0", str(expected)], capture_output=True, text=True)
        print(result.stdout, end="")
        assert result.returncode == expected, result.stderr
        match = re.search(r"flags=0x([0-9a-f]+) ", result.stdout)
        assert match and "residual=0 " in result.stdout
        flags_value = int(match[1], 16)
        assert flags_value != 0xffffffff
        assert (flags_value & bit) == bit if bit else flags_value == 0
    for host in ["discord.com", "mempool.space", "github.com", "api.github.com"]:
        verify(fixtures / (host + "-full.pem"), host, 0)
        verify(fixtures / (host + "-full.pem"), "wrong.example", 2, 4)
    verify(fixtures / "discord.com-short.pem", "discord.com", 0)
    for name, host in [("self.pem", "api.coingecko.com"), ("attacker-full.pem", "discord.com"), ("bad-signature.pem", "discord.com")]:
        verify(fixtures / name, host, 2, 8)
    with zipfile.ZipFile(ROOT / "certificates/test/emudhra-chains-2026-10-20.zip") as archive:
        chains = [name for name in archive.namelist() if name.endswith(".pem")]
        assert len(chains) == 12
        for name in chains:
            chain = build / Path(name).name
            chain.write_bytes(archive.read(name))
            verify(chain, chain.stem, 2, 8)
    for name, host in [("discord.com-full.pem", "wrong.example"), ("bad-signature.pem", "discord.com")]:
        subprocess.run([str(negative), str(fixtures / name), host], check=True)
    print("PASS archived native verifier: positives, hostname/trust/signature/incident negatives; fault cleanup")

if __name__ == "__main__":
    main()
