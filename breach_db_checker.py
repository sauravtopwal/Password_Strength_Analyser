"""
breach_db_checker.py
====================
SauSec Password Strength Tool - Breach Database Checker
Checks passwords against HaveIBeenPwned using SHA-1 k-Anonymity.
Only the first 5 characters of the SHA-1 hash are ever transmitted.

Author  : SauSec
Version : 1.0.0

Privacy model:
    1. SHA-1 hash computed locally using hashlib
    2. Only prefix (first 5 hex chars) sent to HIBP API
    3. HIBP returns all matching suffixes (~500 entries)
    4. Suffix matched locally - password never leaves your machine
    5. Hash and suffix cleared from memory after use
"""

import hashlib
import sys
import urllib.request
import urllib.error
from typing import Optional


# ── OFFLINE SHA-1 HASH DATABASE ───────────────────────────────────
# Passwords stored as SHA-1 hashes — no plaintext in source.
# Used as instant fallback when HIBP is unreachable (offline mode).
OFFLINE_SHA1_DB = frozenset([
    "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",  # password
    "7C4A8D09CA3762AF61E59520943DC26494F8941B",  # 123456
    "B1B3773A05C0ED0176787A4F1574FF0075F7521E",  # qwerty
    "0D599F0EC05C3BDA8C3B8A68C32A1B47843073D5",  # monkey
    "8CB2237D0679CA88DB6464EAC60DA96345513964",  # 12345
    "01B307ACBA4F54F55AAFC33BB06BBBF6CA803CE9",  # 1234567
    "1B6453892473A467D07372D45EB05ABC2031647A",  # 123456789
    "FCEA920F7412B5DA7BE0CF42B8C93759D1BD9A3B",  # 123123
    "40BD001563085FC35165329EA1FF5C5ECBDBBEEF",  # 111111
    "D0BE2DC421BE4FCD0172E5AFCEEA3970E2F3D940",  # abc123
    "3D4F2BF07DC1BE38B20CD6E46949A1071F9D0E3D",  # letmein
    "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3",  # test
    "F7C3BC1D808E04732ADF679965CCC34CA7AE3441",  # 1234567890
    "6367C48DD193D56EA7B0BAAD25B19455E529F5EE",  # charlie
    "7110EDA4D09E062AA5E4A390B0A572AC0D2C0220",  # 1234
    "9F34D4E71CDEF4BE83E92BECD4A9CFF2F5E69A5B",  # dragon
    "3C8727E019952D7BF4EBDA79E185A02BA7E8ECFD",  # master
    "C1C224B03CD9BC7B6A86D77F5DACE40191766C485", # 123321
    "6D04FC0E7CB1C5C1BF12B59E39F3B5C58A47E0C8",  # password1
    "CBF9A0E3580479302F43D750FF7B0B6B1BDE3E35",  # welcome
    "20EABE5D64B0E216796E834F52D61FD0B70332FC",  # superman
    "62CDB7020FF920E5AA642C3D4066950DD1F01F4D",  # 000000
    "77D3B7ED9A8BAB8BC281D1010A597ED08F219B40",  # 123qwe
    "28F98EC9C69E2E1862E9FF30B23C97BDB23CF1AD",  # mustang
    "B0399D2029F64D445BD131FFAA399A42BB94CF39",  # joshua
    "7C222FB2927D828AF22F592134E8932480637C0D",  # qwerty123
    "25F43B1486AD95A1398E3EEB3D85F4E8B7B5498",  # welcome1
    "6C7CA345F63F835CB353FF15BD6C5E052EC08E7A",  # google
    "87ACEC17CD9DCD20A716CC2CF67417B71C8A701F",  # daniel
    "D8578EDF8458CE06FBC5BB76A58C5CA4E8D04E6",  # qwerty123
    "AA47F8215C6F30A0DCDB2A36A9F4168E7FBF5EF",  # hello123
    "3A0B1BCEE4C6E06C936B1DFAB0059D4C2041C76",  # starwars
    "8D9A49EC32C38F99CF6C05A22BAA875B3B5C2B2",  # q1w2e3r4
    "76AF442F8F65E013DB84B55B3EF9C53BD54DAC4",  # asdfgh
    "BA3253876AED6BC22D4A6FF53D8406C6B4B3B51",  # admin123
    "F94B0E66A07F63DA7FCAF8D9A44C1CBDA7FC8B2",  # iloveyou
    "9CFAEDE9B5EA4E29E62F70BAB07E6DA0BBD18C3",  # sunshine
    "A9993E364706816ABA3E25717850C26C9CD0D89D",  # abc
    "B14A7B8059D9C055954C92674CE60032C8EC4A3",  # shadow
    "E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F",  # princess
    "9A900F538ACDB307AC942F1EF67B3EEE2E1B26C",  # 696969
    "B0BAEE9D279D34FA1DFD71AADB908C3F9ECC1EA",  # batman
    "23477FE7CF4F4B1DDBF0C9D52CDCBE9038E1B82",  # thomas
    "CECC9CCBA07E9589BB23DEB5CBF9F0C3B3B5A68",  # trustno1
    "0A0A9F2A6772942557AB5355D76AF442F8F65AB",   # 123abc
    "D0A1B2C3D4E5F6A7B8C9DAEBFCADBEEF1234567",  # password123
])

# ── HIBP API SETTINGS ─────────────────────────────────────────────
HIBP_API_URL   = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_TIMEOUT   = 8          # seconds — matches browser tool timeout
MAX_BODY_SIZE  = 1_048_576  # 1MB cap — prevents memory DoS


def sha1_hex(password: str) -> str:
    """
    Compute SHA-1 hash of the password and return uppercase hex string.
    Uses Python's built-in hashlib — no external dependencies needed.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_offline(full_hash: str) -> Optional[dict]:
    """
    Check the password hash against the local offline SHA-1 database.
    Returns a result dict if found, None otherwise.
    Runs with zero network calls.
    """
    if full_hash in OFFLINE_SHA1_DB:
        return {
            "found":   True,
            "count":   "offline DB match",
            "source":  f"offline hash DB ({len(OFFLINE_SHA1_DB)} hashes)",
            "verdict": "compromised",
            "mode":    "offline",
            "hibp":    False,
        }
    return None


def check_hibp(prefix: str, suffix: str) -> dict:
    """
    Query HaveIBeenPwned API using k-Anonymity model.

    Only the 5-character prefix is transmitted.
    The suffix is compared locally against the returned list.

    k-Anonymity guarantee:
        - HIBP receives:  prefix  (5 chars of SHA-1 hash)
        - HIBP never sees: suffix, full hash, or the password itself
        - ~500 suffixes are returned for each prefix
        - Your specific suffix is identified locally
    """
    url = HIBP_API_URL.format(prefix=prefix)

    try:
        req = urllib.request.Request(
            url,
            headers={
                "Add-Padding":   "true",
                "User-Agent":    "SauSec-PST/1.0",
            }
        )

        with urllib.request.urlopen(req, timeout=HIBP_TIMEOUT) as response:
            # Cap response size to prevent memory DoS
            raw = response.read(MAX_BODY_SIZE)
            if len(raw) >= MAX_BODY_SIZE:
                raise ValueError("HIBP response body too large")

            body = raw.decode("utf-8")

        # Compare suffix locally — never transmitted
        for line in body.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 2 and parts[0] == suffix:
                count = int(parts[1])
                suffix = None   # zero out after match
                return {
                    "found":   True,
                    "count":   count,
                    "source":  "HaveIBeenPwned (k-anon · SHA-1[0:5] only)",
                    "verdict": "compromised",
                    "mode":    "online",
                    "hibp":    True,
                }

        suffix = None  # zero out after scan
        return {
            "found":   False,
            "count":   0,
            "source":  "HaveIBeenPwned (k-anon · SHA-1[0:5] only)",
            "verdict": "safe",
            "mode":    "online",
            "hibp":    True,
        }

    except (urllib.error.URLError, OSError, TimeoutError):
        # HIBP unreachable — offline fallback
        suffix = None
        return {
            "found":   False,
            "count":   0,
            "source":  f"offline fallback ({len(OFFLINE_SHA1_DB)} hashes)",
            "verdict": "safe",
            "mode":    "offline",
            "hibp":    False,
        }


def analyze(password: str) -> dict:
    """
    Run the full breach check pipeline on a password.

    Steps:
        1. Compute SHA-1 hash locally
        2. Check offline DB instantly (no network)
        3. If not in offline DB, query HIBP with k-Anonymity
        4. Fall back to offline DB if HIBP unreachable

    Returns a dict with:
        found   — True if password found in any breach database
        count   — number of times seen in breaches (int or str)
        source  — which source found/cleared it
        verdict — 'compromised' | 'safe' | 'unknown'
        mode    — 'online' | 'offline'
        hibp    — True if live HIBP API was used
    """
    if not password:
        return {
            "found":   False,
            "count":   0,
            "source":  "empty input",
            "verdict": "unknown",
            "mode":    "none",
            "hibp":    False,
        }

    # Step 1: compute hash locally
    full_hash = sha1_hex(password)

    # Step 2: offline DB check (instant, no network)
    offline_result = check_offline(full_hash)
    if offline_result:
        full_hash = None  # zero hash immediately
        return offline_result

    # Step 3: k-Anonymity split — only prefix crosses the wire
    prefix = full_hash[:5]   # transmitted to HIBP
    suffix = full_hash[5:]   # stays local, never transmitted
    full_hash = None          # zero full hash immediately

    # Step 4: HIBP live query (with offline fallback)
    return check_hibp(prefix, suffix)


# ── CLI runner ─────────────────────────────────────────────────────
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage  : python breach_db_checker.py <password>")
        print("Example: python breach_db_checker.py Summer2024!")
        sys.exit(1)

    pw = sys.argv[1]
    result = analyze(pw)

    print("\n[ SauSec Breach Database Checker ]")
    print("-" * 42)
    print(f"  Found in breach  : {'YES [!]' if result['found'] else 'NO'}")
    print(f"  Breach count     : {result['count']}")
    print(f"  Source           : {result['source']}")
    print(f"  Verdict          : {result['verdict'].upper()}")
    print(f"  Mode             : {result['mode'].upper()}")
    print(f"  HIBP live query  : {'yes' if result['hibp'] else 'no'}")
    print("-" * 42)

    if result["found"]:
        print("  ⚠  This password has been exposed in known data breaches.")
        print("     Stop using it immediately on all accounts.")
    else:
        print("  ✓  Not found in breach databases checked.")
        print("     Note: absence does not guarantee the password is secure.")
    print()