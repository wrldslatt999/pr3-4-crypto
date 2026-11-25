"""Повторюваний мікробенчмарк AES/RSA із медіанами, JSON/CSV/Markdown."""
import csv
import io
import json
import os
import platform
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from .formats import safe_write
from . import symmetric, rsa_ops


def parse_size(text):
    s = text.strip().upper()
    mul = 1
    if s.endswith("MB"):
        mul, s = 1024**2, s[:-2]
    elif s.endswith("KB"):
        mul, s = 1024, s[:-2]
    n = int(float(s) * mul)
    if not 1 <= n <= 64 * 1024 * 1024:
        raise ValueError("Size must be between 1 byte and 64 MiB")
    return n


def _measure(fn, repeats):
    samples = []
    result = None
    for _ in range(repeats):
        start = time.perf_counter_ns()
        result = fn()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return result, round(statistics.median(samples), 4), samples


def run(*, sizes=(1024, 65536, 1048576), modes=("gcm", "cbc"),
        rsa_bits=(2048, 3072, 4096), repeats=5):
    if not 2 <= repeats <= 30:
        raise ValueError("Repeats must be 2–30")
    results = []
    for size in sizes:
        data = os.urandom(size)
        master = os.urandom(32)
        for mode in modes:
            # Вимірюємо encryption і decryption з HKDF та пакуванням.
            encrypted, enc_ms, _ = _measure(
                lambda: symmetric.encrypt(data, master, mode=mode), repeats)
            restored, dec_ms, _ = _measure(
                lambda: symmetric.decrypt(encrypted, master), repeats)
            assert restored == data
            results.append({"family": "AES", "algorithm": f"AES-256-{mode.upper()}",
                            "size_bytes": size, "key_bits": 256, "operation": "encrypt", "median_ms": enc_ms})
            results.append({"family": "AES", "algorithm": f"AES-256-{mode.upper()}",
                            "size_bytes": size, "key_bits": 256, "operation": "decrypt", "median_ms": dec_ms})
    for bits in rsa_bits:
        private, keygen_ms, _ = _measure(lambda: rsa_ops.generate(bits)[0], repeats)
        public = private.public_key()
        small = os.urandom(32)
        ciphertext, enc_ms, _ = _measure(lambda: rsa_ops.encrypt(public, small), repeats)
        restored, dec_ms, _ = _measure(lambda: rsa_ops.decrypt(private, ciphertext), repeats)
        signature, sign_ms, _ = _measure(lambda: rsa_ops.sign(private, small), repeats)
        verified, verify_ms, _ = _measure(lambda: rsa_ops.verify(public, signature, small), repeats)
        assert restored == small and verified
        for name, val in (("keygen", keygen_ms), ("encrypt", enc_ms), ("decrypt", dec_ms),
                          ("sign", sign_ms), ("verify", verify_ms)):
            results.append({"family": "RSA", "algorithm": f"RSA-{bits}-OAEP/PSS", "size_bytes": 32,
                            "key_bits": bits, "operation": name, "median_ms": val})
    meta = {"utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
            "python": platform.python_version(), "processor": platform.processor(),
            "machine": platform.machine(), "repeats": repeats,
            "measurement": "median of repeated wall-clock perf_counter_ns, includes format/KDF overhead; no warm-up; non-production benchmark"}
    return meta, results


def save(meta, results, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    safe_write(dest / "results.json", json.dumps({"metadata": meta, "results": results},
               ensure_ascii=False, indent=2).encode("utf-8"), overwrite=True)
    output = io.StringIO()
    fieldnames = ["family", "algorithm", "size_bytes", "key_bits", "operation", "median_ms"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)
    safe_write(dest / "results.csv", output.getvalue().encode("utf-8"), overwrite=True)
    lines = ["# Вимірювання продуктивності AES та RSA", "",
             f"Дата UTC: {meta['utc']}", f"Python: {meta['python']}",
             f"ОС: {meta['platform']}", f"Процесор (доступна мітка): {meta['processor'] or 'не визначено'}",
             f"Повторів для медіани: {meta['repeats']}", "",
             "| Алгоритм | Обсяг (байт) | Операція | Медіана (мс) |",
             "|---|---:|---|---:|"]
    for r in results:
        lines.append(f"| {r['algorithm']} | {r['size_bytes']} | {r['operation']} | {r['median_ms']:.4f} |")
    lines += ["", "## Інтерпретація", "",
              "AES-GCM надає конфіденційність та автентичність одним режимом і є типовим основним вибором.",
              "AES-CBC використано **лише з Encrypt-then-MAC (HMAC-SHA256)** з незалежними ключами,",
              "отриманими через HKDF. Самостійний CBC без MAC не надає автентичності.",
              "RSA-OAEP підходить для коротких повідомлень або транспортування AES-ключа; великі файли — гібридом.",
              "RSA keygen виміряно окремо, його результат залежить від ОС, CPU, OpenSSL та випадковості.",
              "Малі числа можуть мати помітний відносний шум; результати стосуються **цього середовища**,",
              "не порівнюються безпосередньо з результатами Kali чи іншого обладнання.", ""]
    safe_write(dest / "results.md", "\n".join(lines).encode("utf-8"), overwrite=True)
