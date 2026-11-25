"""Functional and negative crypto tests, including teaching-template regressions."""
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from crypto_lab import symmetric, rsa_ops, hybrid
from crypto_lab.formats import CryptoFileError
from crypto_lab.keystore import KeyStore

PASSWORD = "test-passphrase-unique-strong-2026"


@pytest.mark.parametrize("mode", ["gcm", "cbc"])
@pytest.mark.parametrize("bits", [128,192,256])
@pytest.mark.parametrize("payload", [b"", b"Hello", b"\x00\xff"*1001])
def test_aes_roundtrip(mode, bits, payload):
    key = secrets.token_bytes(bits // 8)
    ct = symmetric.encrypt(payload, key, mode=mode, key_id="k1")
    assert symmetric.decrypt(ct, key, expected_kid="k1") == payload
    assert payload not in ct if payload else True


@pytest.mark.parametrize("mode", ["gcm", "cbc"])
def test_aes_authentication_rejects_tampering(mode):
    key = secrets.token_bytes(32)
    blob = bytearray(symmetric.encrypt(b"sealed private data", key, mode=mode))
    blob[-1] ^= 0x10
    with pytest.raises(CryptoFileError):
        symmetric.decrypt(bytes(blob), key)
    with pytest.raises(CryptoFileError):
        symmetric.decrypt(bytes(blob), secrets.token_bytes(32))


@pytest.mark.parametrize("mode", ["gcm", "cbc"])
def test_aes_header_tampering_rejected(mode):
    key = secrets.token_bytes(32)
    blob = bytearray(symmetric.encrypt(b"a", key, mode=mode))
    blob[14] ^= 1
    with pytest.raises(CryptoFileError):
        symmetric.decrypt(bytes(blob), key)


def test_invalid_mode_and_key():
    with pytest.raises(ValueError): symmetric.encrypt(b"x", b"weak", mode="gcm")
    with pytest.raises(ValueError): symmetric.encrypt(b"x", secrets.token_bytes(32), mode="ecb")


def test_key_store_creation_rotation_and_old_decryption(tmp_path):
    ks = KeyStore(tmp_path / "keys")
    one = ks.new("default", 256, PASSWORD)
    key1, meta1 = ks.load("default", PASSWORD)
    ct = symmetric.encrypt(b"old document", key1, key_id=one["kid"])
    two = ks.new("default", 256, PASSWORD, rotate=True)
    assert one["kid"] != two["kid"]
    key2, _ = ks.load("default", PASSWORD)
    assert key1 != key2
    oldkey, _ = ks.load("default", PASSWORD, kid=one["kid"])
    assert symmetric.decrypt(ct, oldkey, expected_kid=one["kid"]) == b"old document"
    with pytest.raises(ValueError): ks.load("default", "wrong-password-that-is-long")
    with pytest.raises(ValueError): ks.new("default", 256, PASSWORD)
    assert oct((tmp_path / "keys" / (one["kid"] + ".json")).stat().st_mode & 0o777) == "0o600"


def test_rsa_key_export_encrypted_and_pem_failure(tmp_path):
    priv, pub = rsa_ops.generate(2048)
    private_file, public_file = tmp_path / "private.pem", tmp_path / "public.pem"
    rsa_ops.save_keys(priv,pub,private_file,public_file,PASSWORD)
    pem = private_file.read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in pem
    assert rsa_ops.load_private(private_file, PASSWORD).key_size == 2048
    assert rsa_ops.load_public(public_file).key_size == 2048
    with pytest.raises(ValueError): rsa_ops.load_private(private_file,"wrong-password-that-is-long")
    public_file.write_text("this is not PEM", encoding="utf-8")
    with pytest.raises(ValueError): rsa_ops.load_public(public_file)


def test_rsa_encrypt_decrypt_sign_verify():
    priv, pub = rsa_ops.generate(2048)
    data = b"small file test"
    assert rsa_ops.decrypt(priv, rsa_ops.encrypt(pub, data)) == data
    sig = rsa_ops.sign(priv, data)
    assert rsa_ops.verify(pub,sig,data)
    assert not rsa_ops.verify(pub,sig,data+b"changed")
    with pytest.raises(ValueError): rsa_ops.encrypt(pub,b"x"*191)  # OAEP-SHA256 limit 190B at 2048 bits.


def test_hybrid_and_wrong_recipient_and_tamper():
    priv, pub = rsa_ops.generate(2048)
    ct = hybrid.encrypt(os.urandom(350_000), pub)
    assert len(hybrid.decrypt(ct,priv)) == 350_000
    other, _ = rsa_ops.generate(2048)
    with pytest.raises(CryptoFileError):hybrid.decrypt(ct,other)
    changed = bytearray(ct);changed[-2] ^= 1
    with pytest.raises(CryptoFileError): hybrid.decrypt(bytes(changed),priv)


def test_hybrid_rejects_bad_header():
    priv,pub = rsa_ops.generate(2048)
    ct=hybrid.encrypt(b"abc",pub)
    with pytest.raises(CryptoFileError):hybrid.decrypt(b"BAD!"+ct[4:], priv)


def run_cli(tmp_path, *args, password=PASSWORD):
    env=dict(os.environ, CRYPTO_PASSWORD=password, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    return subprocess.run([sys.executable,"-m","crypto_lab.cli",*args], cwd=tmp_path,
                          env=env,text=True,capture_output=True)


def test_cli_complete_sym_and_rsa_and_hybrid(tmp_path):
    assert run_cli(tmp_path,"sym","new","--label","default","--bits","256").returncode==0
    assert run_cli(tmp_path,"sym","enc","--label","default","--mode","cbc","--text","text-message","--out","out.cbc").returncode==0
    assert run_cli(tmp_path,"sym","rotate","--label","default").returncode==0
    assert run_cli(tmp_path,"sym","dec","--label","default","--in","out.cbc","--out","out.txt").returncode==0
    assert (tmp_path/"out.txt").read_bytes()==b"text-message"
    assert run_cli(tmp_path,"rsa","gen","--bits","2048","--priv","keys/p.pem","--pub","keys/u.pem").returncode==0
    assert run_cli(tmp_path,"rsa","enc","--pub","keys/u.pem","--text","test","--out","out.rsa").returncode==0
    assert run_cli(tmp_path,"rsa","dec","--priv","keys/p.pem","--in","out.rsa","--out","rsa.dec").returncode==0
    assert (tmp_path/"rsa.dec").read_bytes()==b"test"
    assert run_cli(tmp_path,"rsa","sign","--priv","keys/p.pem","--text","sign-me","--sig","sig.bin").returncode==0
    (tmp_path/"sign-source.txt").write_bytes(b"sign-me")
    assert run_cli(tmp_path,"rsa","verify","--pub","keys/u.pem","--in","sign-source.txt","--sig","sig.bin").returncode==0
    assert run_cli(tmp_path,"hybrid","enc","--pub","keys/u.pem","--text","hybrid proof","--out","a.hybr").returncode==0
    assert run_cli(tmp_path,"hybrid","dec","--priv","keys/p.pem","--in","a.hybr","--out","hybr.dec").returncode==0
    assert (tmp_path/"hybr.dec").read_bytes()==b"hybrid proof"
    logs=(tmp_path/".crypto-lab/logs/operations.jsonl").read_text(encoding="utf-8")
    assert PASSWORD not in logs and "hybrid proof" not in logs
    assert '"status": "success"' in logs


def test_cli_rejects_wrong_key_and_no_output(tmp_path):
    run_cli(tmp_path,"sym","new","--label","a")
    assert run_cli(tmp_path,"sym","enc","--label","a","--text","safe","--out","a.gcm").returncode==0
    bad=bytearray((tmp_path/"a.gcm").read_bytes());bad[-1]^=2
    (tmp_path/"bad.gcm").write_bytes(bad)
    resp=run_cli(tmp_path,"sym","dec","--label","a","--in","bad.gcm","--out","failure.dec")
    assert resp.returncode==2
    assert not (tmp_path/"failure.dec").exists()
    assert run_cli(tmp_path,"sym","dec","--label","a","--in","a.gcm","--out","wrong.dec",password="wrong-password-that-is-long").returncode==2
    assert not (tmp_path/"wrong.dec").exists()
