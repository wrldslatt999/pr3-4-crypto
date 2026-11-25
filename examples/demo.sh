#!/usr/bin/env bash
# Запускати з кореня проєкту; змінну CRYPTO_PASSWORD потрібно виставити локально.
set -euo pipefail
if [[ -z "${CRYPTO_PASSWORD:-}" || ${#CRYPTO_PASSWORD} -lt 12 ]]; then
  echo "Set CRYPTO_PASSWORD to a unique passphrase with >=12 chars" >&2
  exit 1
fi
python cli.py sym new --label demo --bits 256
python cli.py sym enc --label demo --mode gcm --in data/sample.txt --out outputs/sample.gcm
python cli.py sym dec --label demo --in outputs/sample.gcm --out outputs/sample.dec
cmp data/sample.txt outputs/sample.dec
python cli.py sym enc --label demo --mode cbc --in data/sample.txt --out outputs/sample.cbc
python cli.py sym dec --label demo --in outputs/sample.cbc --out outputs/sample.cbc.dec
cmp data/sample.txt outputs/sample.cbc.dec
python cli.py rsa gen --bits 3072 --priv keys/priv.pem --pub keys/pub.pem
python cli.py rsa sign --priv keys/priv.pem --in data/sample.txt --sig outputs/sample.sig
python cli.py rsa verify --pub keys/pub.pem --in data/sample.txt --sig outputs/sample.sig
python cli.py rsa enc --pub keys/pub.pem --in data/sample.txt --out outputs/sample.rsa
python cli.py rsa dec --priv keys/priv.pem --in outputs/sample.rsa --out outputs/sample.rsa.dec
cmp data/sample.txt outputs/sample.rsa.dec
python cli.py hybrid enc --pub keys/pub.pem --in data/sample.txt --out outputs/sample.hybr
python cli.py hybrid dec --priv keys/priv.pem --in outputs/sample.hybr --out outputs/sample.hybr.dec
cmp data/sample.txt outputs/sample.hybr.dec
python cli.py sym rotate --label demo
python cli.py sym list
printf 'All CLI demonstrations completed successfully.\n'
