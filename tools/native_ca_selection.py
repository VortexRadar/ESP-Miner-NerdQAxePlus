#!/usr/bin/env python3
"""Run offline all-root selection and fault tests with the lineage's pinned SDK.

Uses a separate native mbedTLS build, never modifies SDK sources or devices.
"""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PINNED = {"79e3454c68248bd7d881721c9b2e94561378a8ce", "6db3dc25df7325c1c81b7cd7d4e42babff7a818e"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idf-path", type=Path, default=os.environ.get("IDF_PATH"), required=not os.environ.get("IDF_PATH"))
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    sdk = args.idf_path.resolve()
    build = args.build_dir.resolve()
    sha = subprocess.check_output(["git", "-C", str(sdk), "rev-parse", "HEAD"], text=True).strip()
    if sha not in PINNED:
        raise SystemExit("Use the unchanged lineage SDK 5.3.6 or 5.3.3")
    subprocess.run(["git", "-C", str(sdk), "diff", "--exit-code", "HEAD", "--", "components/mbedtls"], check=True)
    subprocess.run([os.sys.executable, str(ROOT / "tools/generate_real_roots.py"), "--check"], check=True)
    source = sdk / "components/mbedtls/mbedtls"
    flags = "-DMBEDTLS_PLATFORM_MEMORY -DMBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK"
    if os.uname().sysname == "Darwin":
        flags += " -Wno-error=unterminated-string-initialization"
    subprocess.run(["cmake", "-S", str(source), "-B", str(build), "-DENABLE_TESTING=OFF", "-DENABLE_PROGRAMS=OFF", "-DCMAKE_C_FLAGS=" + flags], check=True)
    subprocess.run(["cmake", "--build", str(build), "--parallel", "4"], check=True)
    executable = build / "ca-selection"
    libs = [str(build / "library" / ("lib" + name + ".a")) for name in ["mbedtls", "mbedx509", "mbedcrypto"]]
    subprocess.run([os.environ.get("CC", "cc"), "-O2", *flags.split(), "-I" + str(source / "include"), "-I" + str(ROOT / "main"), str(ROOT / "tools/native_ca_selection.c"), str(ROOT / "main/real_roots.c"), *libs, "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

if __name__ == "__main__":
    main()
