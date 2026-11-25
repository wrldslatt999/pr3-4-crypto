# ПР №3–4. Реалізація симетричного/асиметричного шифрування

**Навчальний проєкт** · Чучула Євгеній · Python 3.10+ · AES-128/192/256 · RSA 2048/3072/4096 · GCM/CBC-HMAC · RSA-PSS · hybrid.

Розроблено за структурою додатку викладача (`sym.py`, `asym.py`, `hybrid.py`, `cli.py`, `logger.py`), але небезпечні або неробочі місця шаблону виправлено. Зокрема, вихідний CBC-варіант використовував **різні HMAC-ключі** під час шифрування та дешифрування; поточна реалізація виводить AES та HMAC ключі через HKDF із спільного майстер-ключа.

## Реалізовані завдання

1. **AES:** GCM (AEAD) і CBC + HMAC-SHA256; створення випадкового ключа, salt, захищений keystore (Scrypt + AES-GCM), ротація ключів.
2. **RSA:** ключі 2048/3072/4096, зашифрований PKCS#8 PEM, OAEP-SHA256 для коротких файлів, RSA-PSS-SHA256 для підписів.
3. **Гібрид:** випадковий AES-256-GCM ключ для кожного файлу, загорнутий RSA-OAEP-SHA256 публічним ключем отримувача; перевірка AES-GCM tag.
4. **Тестування продуктивності:** AES-GCM/CBC на різних обсягах, RSA 2048/3072/4096 (генерація ключа, encrypt/decrypt/sign/verify), медіани, `benchmarks/results.csv/json/md`. Негативні сценарії в pytest.
5. **CLI:** команди `sym`, `rsa`, `hybrid`, `bench`; введення файлу або `--text`, автоматичний вивід часу, журнал JSONL, валідація ключів/помилок.

## Публікація для Moodle

Після розпакування ZIP на Kali, де вже виконано `gh auth login`, у корені проєкту запусти:

```bash
bash scripts/publish-github.sh
```

Скрипт **питає підтвердження**, створює новий **приватний** репозиторій `wrldslatt999/pr3-4-crypto` (або під поточним GitHub-акаунтом) і завантажує код через Git. Якщо потрібен інший репозиторій: `bash scripts/publish-github.sh owner/repo`. У Moodle здати URL цього репозиторію; викладачу може знадобитися доступ до приватного репозиторію.

## Встановлення

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

### Пароль для демонстрації

Введи **власну локальну парольну фразу** (не публікуй її), Python запропонує її через `getpass` при TTY. Для автоматизованих скриптів пароль можна встановити в змінну середовища `CRYPTO_PASSWORD`, але **не вносити пароль до репозиторію**:

```bash
read -rsp 'CRYPTO_PASSWORD: ' CRYPTO_PASSWORD; echo
export CRYPTO_PASSWORD
```

Мінімум 12 символів; для реальних секретів краще використовувати довгу випадкову фразу. Після роботи: `unset CRYPTO_PASSWORD`.

## 1. AES: симетричне шифрування

```bash
python cli.py sym new --label default --bits 256
python cli.py sym enc --label default --mode gcm --in data/sample.txt --out outputs/sample.gcm
python cli.py sym dec --label default --in outputs/sample.gcm --out outputs/sample.gcm.dec
cmp data/sample.txt outputs/sample.gcm.dec

python cli.py sym enc --label default --mode cbc --in data/sample.txt --out outputs/sample.cbc
python cli.py sym dec --label default --in outputs/sample.cbc --out outputs/sample.cbc.dec
cmp data/sample.txt outputs/sample.cbc.dec

python cli.py sym rotate --label default
python cli.py sym list
# Старі ciphertext не зламаються: їхній key-id збережений у заголовку.
```

## 2. RSA: ключі, короткий файл, підпис

```bash
python cli.py rsa gen --priv keys/priv.pem --pub keys/pub.pem --bits 3072
python cli.py rsa enc --pub keys/pub.pem --in data/sample.txt --out outputs/sample.rsa
python cli.py rsa dec --priv keys/priv.pem --in outputs/sample.rsa --out outputs/sample.rsa.dec
cmp data/sample.txt outputs/sample.rsa.dec
python cli.py rsa sign --priv keys/priv.pem --in data/sample.txt --sig outputs/sample.sig
python cli.py rsa verify --pub keys/pub.pem --in data/sample.txt --sig outputs/sample.sig
```

RSA-OAEP має обмеження на розмір повідомлення (`k - 2*hLen - 2`), тому довгі файли шифрувати через `hybrid`.

## 3. Гібридний обмін

```bash
python cli.py hybrid enc --pub keys/pub.pem --in data/sample.txt --out outputs/sample.hybr
python cli.py hybrid dec --priv keys/priv.pem --in outputs/sample.hybr --out outputs/sample.hybr.dec
cmp data/sample.txt outputs/sample.hybr.dec

# Приклад вводу тексту замість файлу:
python cli.py hybrid enc --pub keys/pub.pem --text 'Секретне повідомлення' --out outputs/text.hybr
```

## 4. Вимірювання й тести

```bash
python -m pytest -v
python cli.py bench --sizes 1KB 64KB 1MB --modes gcm cbc --rsa-bits 2048 3072 4096 --repeats 5 --out benchmarks
```

Результат `benchmarks/results.md` — таблиця **реальних** вимірювань у поточному середовищі; на Kali числові значення відрізнятимуться. Результат CI/контейнера не можна представляти як виміряний на Kali.

## 5. Помилки й журнал

Пошкоджені ciphertext, неправильний PEM, хибний пароль, невдалий підпис, невірний тег GCM/HMAC та повторне збереження в існуючий файл приводять до явної помилки; файл розшифрованого результату **не створюється** після невдалої перевірки. Події журналюються в `.crypto-lab/logs/operations.jsonl` без plaintext, паролів, секретів, назв файлів.

**Застереження:** навчальний прототип, не production KMS. Вміст файлів читається у пам'ять (до 64 MiB), приватні ключі зберігаються в захищених PEM, а згенеровані ключі AES — у зашифрованому key store. У Windows права на файли реалізуються ACL, не Unix `chmod`.

## Матеріали

- [Повний звіт за завданнями 1–5](docs/PR3-4_report.md)
- [Архітектура](docs/architecture.md)
- [Безпека, генерація ключів, ротація, винятки](docs/security-and-limits.md)
- [Тести й облік перевірок](docs/testing.md)
- [Протокол фактичного запуску тестів і CLI](docs/verification.md)
- [Аналіз фактичних показників продуктивності](docs/bench-analysis.md)
- [Таблиця реальних бенчмарків](benchmarks/results.md)

**Джерела:**
- https://cryptography.io/en/stable/hazmat/primitives/aead/
- https://cryptography.io/en/stable/hazmat/primitives/symmetric-encryption/
- https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/
- https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
