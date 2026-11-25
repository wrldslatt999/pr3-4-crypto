"""CLI для симетрії, RSA, підписів, гібридного режиму і бенчмарків."""
import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from . import rsa_ops, symmetric, hybrid, benchmark
from .audit import get_logger
from .formats import read_input, safe_write
from .keystore import KeyStore


def secret_password():
    value = os.environ.get("CRYPTO_PASSWORD")
    if value is not None:
        if len(value) < 12:
            raise ValueError("CRYPTO_PASSWORD must contain 12+ characters")
        return value
    if not sys.stdin.isatty():
        raise ValueError("Set CRYPTO_PASSWORD (12+ chars) or run interactively to enter passphrase")
    value = getpass.getpass("Passphrase (will not echo): ")
    if len(value) < 12:
        raise ValueError("Passphrase must contain 12+ characters")
    return value


def load_payload(args):
    if getattr(args, "text", None) is not None:
        return args.text.encode("utf-8")
    return read_input(args.infile)


def add_payload(group):
    mutex = group.add_mutually_exclusive_group(required=True)
    mutex.add_argument("--in", dest="infile", help="Input file")
    mutex.add_argument("--text", help="Input UTF-8 text")


def parser():
    p = argparse.ArgumentParser(description="ПР №3–4: AES, RSA, hybrid, підписи та бенчмарки")
    p.add_argument("--store", default=".crypto-lab/keys", help="Directory for encrypted AES key versions")
    p.add_argument("--log", default=".crypto-lab/logs/operations.jsonl")
    sp = p.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("sym", help="AES symmetric key management, encryption and decryption")
    q = s.add_subparsers(dest="action", required=True)
    for name in ("new", "rotate"):
        x = q.add_parser(name)
        x.add_argument("--label", required=True)
        x.add_argument("--bits", type=int, choices=[128,192,256], default=256)
    x = q.add_parser("list")
    x = q.add_parser("enc")
    x.add_argument("--label", required=True)
    x.add_argument("--mode", choices=["gcm", "cbc"], default="gcm")
    add_payload(x)
    x.add_argument("--out", required=True)
    x = q.add_parser("dec")
    x.add_argument("--label", required=True)
    x.add_argument("--in", dest="infile", required=True)
    x.add_argument("--out", required=True)

    r = sp.add_parser("rsa", help="RSA-OAEP and RSA-PSS")
    q = r.add_subparsers(dest="action", required=True)
    x = q.add_parser("gen")
    x.add_argument("--bits", type=int, choices=list(rsa_ops.BITS), default=3072)
    x.add_argument("--priv", required=True)
    x.add_argument("--pub", required=True)
    for name in ("enc", "dec", "sign", "verify"):
        x = q.add_parser(name)
        x.add_argument("--priv" if name in ("dec", "sign") else "--pub", required=True)
        if name in ("enc", "dec", "sign"):
            add_payload(x)
            x.add_argument("--sig" if name == "sign" else "--out", required=True)
        else:
            x.add_argument("--in", dest="infile", required=True)
            x.add_argument("--sig", required=True)

    h = sp.add_parser("hybrid", help="AES-256-GCM encrypted payload with RSA-OAEP wrapped key")
    q = h.add_subparsers(dest="action", required=True)
    x = q.add_parser("enc")
    x.add_argument("--pub", required=True)
    add_payload(x)
    x.add_argument("--out", required=True)
    x = q.add_parser("dec")
    x.add_argument("--priv", required=True)
    x.add_argument("--in", dest="infile", required=True)
    x.add_argument("--out", required=True)

    b = sp.add_parser("bench", help="AES/CBC and RSA microbenchmarks")
    b.add_argument("--sizes", nargs="+", default=["1KB", "64KB", "1MB"])
    b.add_argument("--modes", nargs="+", choices=["gcm", "cbc"], default=["gcm", "cbc"])
    b.add_argument("--rsa-bits", nargs="+", choices=list(rsa_ops.BITS), type=int,
                   default=[2048, 3072, 4096])
    b.add_argument("--repeats", type=int, default=5)
    b.add_argument("--out", default="benchmarks")
    return p


def execute(args):
    if args.cmd == "sym":
        store = KeyStore(args.store)
        if args.action == "list":
            for meta in store.list_metadata():
                print(f"label={meta['label']} versions={meta['versions']} active={meta['active_kid']}")
            return {"algorithm":"KEY-METADATA", "bytes":0,"key_bits":0}
        password = secret_password()
        if args.action in ("new", "rotate"):
            meta = store.new(args.label, args.bits, password, rotate=(args.action=="rotate"))
            print(f"Protected AES-{meta['bits']} key id={meta['kid']} created; raw key never displayed")
            return {"algorithm":"AES-KEY-STORE", "key_bits":meta["bits"],"bytes":0}
        if args.action == "enc":
            key, meta = store.load(args.label, password)
            data = load_payload(args)
            safe_write(args.out, symmetric.encrypt(data, key, mode=args.mode, key_id=meta["kid"]))
            return {"algorithm": f"AES-{meta['bits']}-{args.mode.upper()}","key_bits":meta["bits"],"bytes":len(data)}
        blob = read_input(args.infile)
        kid = symmetric.peek_key_id(blob)
        key, meta = store.load(args.label, password, kid=kid)
        data = symmetric.decrypt(blob, key, expected_kid=kid)
        safe_write(args.out, data)
        return {"algorithm":f"AES-{meta['bits']}-authenticated","key_bits":meta["bits"],"bytes":len(data)}
    if args.cmd == "rsa":
        if args.action == "gen":
            private, public = rsa_ops.generate(args.bits)
            rsa_ops.save_keys(private, public, args.priv, args.pub, secret_password())
            return {"algorithm":"RSA-PKCS8-PEM", "key_bits":args.bits, "bytes":0}
        if args.action == "verify":
            public = rsa_ops.load_public(args.pub)
            valid = rsa_ops.verify(public, read_input(args.sig), read_input(args.infile))
            print("Signature: VALID" if valid else "Signature: INVALID")
            if not valid:
                raise ValueError("Signature verification failed")
            return {"algorithm":"RSA-PSS-SHA256","key_bits":public.key_size,"bytes":0}
        key = (rsa_ops.load_public(args.pub) if args.action == "enc" else
               rsa_ops.load_private(args.priv, secret_password()))
        data = load_payload(args)
        if args.action == "enc":
            result = rsa_ops.encrypt(key, data)
        elif args.action == "dec":
            result = rsa_ops.decrypt(key, data)
        else:
            result = rsa_ops.sign(key, data)
        safe_write(args.sig if args.action == "sign" else args.out, result)
        alg = "RSA-PSS-SHA256" if args.action == "sign" else "RSA-OAEP-SHA256"
        return {"algorithm":alg,"key_bits":key.key_size,"bytes":len(data)}
    if args.cmd == "hybrid":
        key = (rsa_ops.load_public(args.pub) if args.action == "enc" else
               rsa_ops.load_private(args.priv, secret_password()))
        data = load_payload(args) if args.action == "enc" else read_input(args.infile)
        result = (hybrid.encrypt(data,key) if args.action == "enc" else hybrid.decrypt(data,key))
        safe_write(args.out,result)
        return {"algorithm":"AES-256-GCM+RSA-OAEP-SHA256", "key_bits":key.key_size,"bytes":len(data)}
    if args.cmd == "bench":
        sizes = [benchmark.parse_size(s) for s in args.sizes]
        meta, res = benchmark.run(sizes=sizes, modes=args.modes,
                                  rsa_bits=args.rsa_bits, repeats=args.repeats)
        benchmark.save(meta, res, args.out)
        print(f"Benchmark data: {args.out}/results.md, results.csv, results.json")
        return {"algorithm":"AES+RSA-BENCHMARK", "key_bits":0, "bytes":sum(sizes)}
    raise ValueError("Unsupported command")


def main(argv=None):
    args = parser().parse_args(argv)
    log = get_logger(args.log)
    started = time.perf_counter()
    try:
        result = execute(args)
        elapsed_ms = round((time.perf_counter() - started)*1000,3)
        log.info("crypto_operation",extra={"operation":f"{args.cmd}.{getattr(args, 'action', 'run')}",
                 "algorithm":result["algorithm"],"key_bits":result["key_bits"],
                 "bytes":result["bytes"],"elapsed_ms":elapsed_ms,"status":"success"})
        print(f"OK | {result['algorithm']} | key={result['key_bits']} bits | data={result['bytes']} B | {elapsed_ms:.3f} ms")
    except (ValueError, OSError, TypeError, KeyError) as exc:
        log.error("crypto_operation",extra={"operation":f"{args.cmd}.{getattr(args, 'action', 'run')}",
                  "elapsed_ms":round((time.perf_counter()-started)*1000,3),
                  "status":"failed", "error":type(exc).__name__})
        print(f"ERROR [{type(exc).__name__}]: {exc}",file=sys.stderr)
        raise SystemExit(2) from None

if __name__ == "__main__":
    main()
