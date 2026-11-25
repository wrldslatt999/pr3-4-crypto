# Протокол перевірки працездатності (25.11.2026)

**Об'єкт:** локальний проєкт за `додаток_пр_3-4.rar`.

## Автоматизовані тести

Виконано:

```bash
python -m pytest -q
```

Реальний результат:

```text
..............................                                           [100%]
30 passed in 20.80s
```

Це результати тестів **у середовищі створення проєкту**, а не результат незалежного запуску GitHub Actions або Kali Linux. Після публікації у GitHub CI запустить такий самий набір через `.github/workflows/tests.yml`.

## End-to-end CLI

Запуск `examples/demo.sh` із тимчасовим паролем, створеним локально через CSPRNG:

- Створення AES-256 ключа в захищеному keystore — OK.
- AES-256-GCM encrypt/decrypt і `cmp` — OK.
- AES-256-CBC+HMAC encrypt/decrypt і `cmp` — OK.
- RSA-3072 key generation, PEM export — OK.
- RSA-PSS sign, verify — `Signature: VALID`.
- RSA-OAEP encrypt/decrypt і `cmp` — OK.
- Hybrid AES-GCM+RSA-OAEP encrypt/decrypt і `cmp` — OK.
- `sym rotate`: попередня й нова версії ключа збережені — OK.
- Команда без змінної `CRYPTO_PASSWORD` в non-interactive сценарії безпечно відмовляється працювати — OK.
- Пошук пароля у JSONL-журналі не дав збігів; лог не містить plaintext — OK.

**Секрети не включено до архіву або репозиторію**; `.gitignore` виключає `.crypto-lab/`, `keys/`, `outputs/`, `logs/`.

## Вимірювання

`python cli.py bench --sizes 1KB 64KB 1MB --modes gcm cbc --rsa-bits 2048 3072 4096 --repeats 5 --out benchmarks` — OK, сформовано три файли результатів. Середовище Python 3.13.5 / Linux x86_64 / `cryptography` 46.0.4. Дані не можна вважати результатами Kali.

## Необхідна перевірка після публікації

У вкладці **Actions** новоствореного репозиторію має з'явитися workflow `Cryptographic unit and integration tests`. Для повного документування можна додати скриншот із зеленим статусом, часом і назвою коміту.
