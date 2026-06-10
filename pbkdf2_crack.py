#!/usr/bin/env python3
"""
pbkdf2_crack.py — PBKDF2-SHA256 Password Cracker
==================================================

Descrição:
    Quebra hashes PBKDF2-HMAC-SHA256 via força bruta com wordlist.
    Suporta múltiplos formatos encontrados em diferentes aplicações.

Formatos suportados (--format):
    grafana     Grafana >= 6.x
                  DB: select password, salt from user
                  Formato raw: <hex_hash>:<salt_plaintext>
                  Iterações: 10000 | dklen: 50

    django      Django (Passlib PBKDF2PasswordHasher)
                  Formato: pbkdf2_sha256$<iter>$<salt>$<b64hash>
                  Iterações: variável | dklen: 32

    passlib     Passlib genérico
                  Formato: $pbkdf2-sha256$<iter>$<b64salt>$<b64hash>
                  Iterações: variável | dklen: 32

    raw         Modo manual — você passa hash, salt, iter e dklen
                  Requer: --hash, --salt, --iterations, --dklen

Uso:
    python3 pbkdf2_crack.py --format grafana --hash <hex> --salt <salt> [opções]
    python3 pbkdf2_crack.py --format django  --token 'pbkdf2_sha256$...' [opções]
    python3 pbkdf2_crack.py --format passlib --token '$pbkdf2-sha256$...' [opções]
    python3 pbkdf2_crack.py --format raw --hash <hex> --salt <txt> --iterations 10000 --dklen 32 [opções]

Exemplos:
    # Grafana
    python3 pbkdf2_crack.py --format grafana \\
        --hash d0dbe567951b6d460c481eefe7ac5d582466f3d518870b1f70a68ac297739cb3345155c1f9d2544ba3f343e8dd39cdb51784 \\
        --salt Uzkmhw7RLV

    # Django
    python3 pbkdf2_crack.py --format django \\
        --token 'pbkdf2_sha256$260000$salt$hash='

    # Passlib
    python3 pbkdf2_crack.py --format passlib \\
        --token '$pbkdf2-sha256$29000$c3RyaW5n$hash='

    # Raw (manual)
    python3 pbkdf2_crack.py --format raw \\
        --hash aabbcc... --salt mysalt --iterations 10000 --dklen 32

    # Wordlist customizada + threads
    python3 pbkdf2_crack.py --format grafana \\
        --hash <hash> --salt <salt> \\
        --wordlist /usr/share/wordlists/fasttrack.txt --threads 8

Referências:
    Grafana CVE-2021-43798 : https://nvd.nist.gov/vuln/detail/CVE-2021-43798
    Django password hashing: https://docs.djangoproject.com/en/stable/topics/auth/passwords/
    Passlib PBKDF2         : https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html
"""

import argparse
import base64
import hashlib
import sys
import time
from multiprocessing import Pool


DEFAULT_WORDLIST = '/usr/share/wordlists/rockyou.txt'
DEFAULT_THREADS  = 4
DEFAULT_CHUNK    = 100


# ──────────────────────────────────────────
# Parsers de formato
# ──────────────────────────────────────────

def parse_grafana(args):
    """
    Grafana: hash hexadecimal + salt em texto plano extraídos do SQLite.
    sqlite3 grafana.db "select password, salt from user;"
    """
    if not args.hash or not args.salt:
        print('[!] --format grafana requer --hash e --salt')
        sys.exit(1)
    return {
        'hash_hex'  : args.hash.strip().lower(),
        'salt'      : args.salt.strip().encode(),
        'iterations': 10000,
        'dklen'     : 50,
    }


def parse_django(args):
    """
    Django: pbkdf2_sha256$<iterations>$<salt>$<b64hash>
    """
    if not args.token:
        print('[!] --format django requer --token')
        sys.exit(1)
    try:
        _, iterations, salt, b64hash = args.token.strip().split('$')
        hash_bytes = base64.b64decode(b64hash + '==')
        return {
            'hash_hex'  : hash_bytes.hex(),
            'salt'      : salt.encode(),
            'iterations': int(iterations),
            'dklen'     : len(hash_bytes),
        }
    except Exception as e:
        print(f'[!] Erro ao parsear token Django: {e}')
        sys.exit(1)


def parse_passlib(args):
    """
    Passlib: $pbkdf2-sha256$<iterations>$<b64salt>$<b64hash>
    """
    if not args.token:
        print('[!] --format passlib requer --token')
        sys.exit(1)
    try:
        parts = args.token.strip().lstrip('$').split('$')
        # formato: pbkdf2-sha256 | iterations | b64salt | b64hash
        _, iterations, b64salt, b64hash = parts
        # Passlib usa base64 modificado (sem padding, substituição de chars)
        def passlib_b64decode(s):
            s = s.replace('.', '+')
            pad = 4 - len(s) % 4
            if pad != 4:
                s += '=' * pad
            return base64.b64decode(s)
        salt_bytes = passlib_b64decode(b64salt)
        hash_bytes = passlib_b64decode(b64hash)
        return {
            'hash_hex'  : hash_bytes.hex(),
            'salt'      : salt_bytes,
            'iterations': int(iterations),
            'dklen'     : len(hash_bytes),
        }
    except Exception as e:
        print(f'[!] Erro ao parsear token Passlib: {e}')
        sys.exit(1)


def parse_raw(args):
    """
    Modo raw: todos os parâmetros passados manualmente.
    """
    missing = [f for f in ['hash', 'salt', 'iterations', 'dklen'] if not getattr(args, f, None)]
    if missing:
        print(f'[!] --format raw requer: {", ".join("--"+m for m in missing)}')
        sys.exit(1)
    return {
        'hash_hex'  : args.hash.strip().lower(),
        'salt'      : args.salt.strip().encode(),
        'iterations': args.iterations,
        'dklen'     : args.dklen,
    }


FORMAT_PARSERS = {
    'grafana': parse_grafana,
    'django' : parse_django,
    'passlib': parse_passlib,
    'raw'    : parse_raw,
}


# ──────────────────────────────────────────
# Cracking
# ──────────────────────────────────────────

def make_checker(hash_hex, salt, iterations, dklen):
    def check(pwd):
        try:
            dk = hashlib.pbkdf2_hmac(
                'sha256',
                pwd.encode('latin-1'),
                salt,
                iterations,
                dklen=dklen,
            )
            return dk.hex() == hash_hex, pwd
        except Exception:
            return False, pwd
    return check


def crack(params, wordlist_path, threads, chunk, verbose):
    check = make_checker(
        params['hash_hex'],
        params['salt'],
        params['iterations'],
        params['dklen'],
    )

    try:
        with open(wordlist_path, 'r', encoding='latin-1') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f'[!] Wordlist não encontrada: {wordlist_path}')
        sys.exit(1)

    total = len(passwords)
    print(f'[*] {total:,} senhas carregadas | threads={threads} | dklen={params["dklen"]} | iter={params["iterations"]:,}')
    print(f'[*] Iniciando...\n')

    start = time.time()
    try:
        with Pool(threads) as pool:
            for i, (found, pwd) in enumerate(
                pool.imap(check, passwords, chunksize=chunk)
            ):
                if found:
                    elapsed = time.time() - start
                    print(f'\n[+] SENHA ENCONTRADA : {pwd}')
                    print(f'[i] Tentativas       : {i+1:,}')
                    print(f'[i] Tempo            : {elapsed:.1f}s')
                    print(f'[i] Velocidade média : {(i+1)/elapsed:.0f} h/s')
                    return pwd

                if verbose and i % 10000 == 0 and i > 0:
                    elapsed = time.time() - start
                    rate = i / elapsed if elapsed > 0 else 0
                    pct  = i / total * 100
                    print(
                        f'[*] {i:>8,}/{total:,} ({pct:5.1f}%) | '
                        f'{rate:6.0f} h/s | {pwd[:30]}',
                        end='\r',
                    )

    except KeyboardInterrupt:
        print('\n[!] Interrompido pelo usuário')
        sys.exit(1)

    elapsed = time.time() - start
    print(f'\n[-] Senha não encontrada | {total:,} tentativas | {elapsed:.1f}s')
    return None


# ──────────────────────────────────────────
# CLI
# ──────────────────────────────────────────

def banner():
    print("""
╔══════════════════════════════════════════════╗
║        PBKDF2-SHA256 Password Cracker        ║
║  grafana | django | passlib | raw            ║
╚══════════════════════════════════════════════╝
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description='PBKDF2-SHA256 Password Cracker — suporta Grafana, Django, Passlib e modo raw',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Formato
    parser.add_argument('--format', choices=FORMAT_PARSERS.keys(), required=True,
                        help='Formato do hash: grafana | django | passlib | raw')

    # Dados do hash
    parser.add_argument('--hash',       help='Hash em hexadecimal (grafana/raw)')
    parser.add_argument('--salt',       help='Salt em texto plano (grafana/raw)')
    parser.add_argument('--token',      help='Token completo (django/passlib)')
    parser.add_argument('--iterations', type=int, help='Iterações PBKDF2 (raw)')
    parser.add_argument('--dklen',      type=int, help='Tamanho do derived key em bytes (raw)')

    # Opções de cracking
    parser.add_argument('-w', '--wordlist', default=DEFAULT_WORDLIST,
                        help=f'Wordlist (padrão: {DEFAULT_WORDLIST})')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS,
                        help=f'Threads paralelas (padrão: {DEFAULT_THREADS})')
    parser.add_argument('-c', '--chunk', type=int, default=DEFAULT_CHUNK,
                        help=f'Chunk size por worker (padrão: {DEFAULT_CHUNK})')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Mostra progresso a cada 10.000 tentativas')

    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    parser_fn = FORMAT_PARSERS[args.format]
    params = parser_fn(args)

    print(f'[i] Formato    : {args.format}')
    print(f'[i] Hash       : {params["hash_hex"][:32]}...')
    print(f'[i] Salt       : {params["salt"].decode(errors="replace")}')
    print(f'[i] Iterações  : {params["iterations"]:,}')
    print(f'[i] dklen      : {params["dklen"]} bytes')
    print(f'[i] Wordlist   : {args.wordlist}')
    print()

    crack(params, args.wordlist, args.threads, args.chunk, args.verbose)


if __name__ == '__main__':
    main()
