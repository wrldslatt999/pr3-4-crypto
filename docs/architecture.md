# Архітектура й потоки даних

```mermaid
flowchart LR
 U[Користувач] --> CLI[CLI / cli.py]
 CLI --> K[KeyStore: Scrypt + AES-GCM]
 CLI --> AES[AES-GCM / AES-CBC+HMAC]
 CLI --> RSA[RSA-OAEP / RSA-PSS]
 CLI --> HYB[Hybrid: RSA-OAEP + AES-256-GCM]
 CLI --> B[Benchmarks: perf_counter_ns]
 CLI --> L[JSONL audit logger]
 K -->|Відновлений AES ключ у пам'яті| AES
 RSA -->|Публічний / приватний ключ PEM| HYB
 HYB -->|Файл CSYM/CHYB| F[Зашифрований вихід]
 AES --> F
```

## Контейнери

- `CSYM | uint16 header_len | canonical UTF-8 JSON | encrypted data | authentication tag`.
- `CHYB | uint16 header_len | JSON | RSA-OAEP(wrapped AES-256 key) | AES-GCM ciphertext+tag`.
- Заголовок AES прив'язаний як AAD або HMAC-вхід; будь-яка зміна salt, IV/nonce, key-id має бути виявлена.
- Для CBC окремий 256-bit MAC-ключ виводиться через HKDF зі спільного майстер-ключа, *не* записується в контейнері.
- Ключі AES зберігаються окремими зашифрованими версіями: Scrypt(password, random salt) → AES-GCM encrypted master key.
