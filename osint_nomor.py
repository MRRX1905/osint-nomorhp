import argparse
import json
import os
import re
import sys
from urllib.parse import quote

import requests

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "osint-nomor-indo/1.0"

OPERATOR = {
    "62811": "Telkomsel",
    "62812": "Telkomsel",
    "62813": "Telkomsel",
    "62821": "Telkomsel",
    "62822": "Telkomsel",
    "62823": "Telkomsel",
    "62851": "Telkomsel",
    "62852": "Telkomsel",
    "62853": "Telkomsel",
    "62814": "Indosat Ooredoo",
    "62815": "Indosat Ooredoo",
    "62816": "Indosat Ooredoo",
    "62855": "Indosat Ooredoo",
    "62856": "Indosat Ooredoo",
    "62857": "Indosat Ooredoo",
    "62858": "Indosat Ooredoo",
    "62817": "XL Axiata",
    "62818": "XL Axiata",
    "62859": "XL Axiata",
    "62877": "XL Axiata",
    "62878": "XL Axiata",
    "62831": "XL Axiata (Axis)",
    "62832": "XL Axiata (Axis)",
    "62833": "XL Axiata (Axis)",
    "62838": "XL Axiata (Axis)",
    "62895": "Tri (3)",
    "62896": "Tri (3)",
    "62897": "Tri (3)",
    "62898": "Tri (3)",
    "62899": "Tri (3)",
    "62881": "Smartfren",
    "62882": "Smartfren",
    "62883": "Smartfren",
    "62884": "Smartfren",
    "62885": "Smartfren",
    "62886": "Smartfren",
    "62887": "Smartfren",
    "62888": "Smartfren",
    "62889": "Smartfren",
}


def normalize(raw: str) -> str:
    s = re.sub(r"[\s\-\.()\[\]]", "", raw)
    s = s.lstrip("+")
    if s.startswith("0"):
        s = "62" + s[1:]
    elif s.startswith("8") and not s.startswith("62"):
        s = "62" + s
    if not re.fullmatch(r"62\d{9,12}", s):
        raise ValueError(f"format nomor tidak valid: {raw}")
    return s


def deteksi_operator(e164: str) -> str:
    return OPERATOR.get(e164[:5], "tidak dikenal")


def hibp_headers(api_key: str) -> dict:
    return {"hibp-api-key": api_key, "user-agent": USER_AGENT}


def cek_breach(e164: str, api_key: str) -> dict:
    url = f"{HIBP_BASE}/breachedaccount/{quote(e164)}"
    r = requests.get(url, headers=hibp_headers(api_key), params={"truncateResponse": "false"}, timeout=30)
    if r.status_code == 200:
        return {"status": "bocor", "data": r.json()}
    if r.status_code == 404:
        return {"status": "bersih", "data": []}
    if r.status_code == 401:
        return {"status": "error", "data": "API key HIBP tidak valid atau tidak diset"}
    if r.status_code == 429:
        return {"status": "error", "data": "rate limit HIBP, coba lagi nanti"}
    return {"status": "error", "data": f"HTTP {r.status_code}: {r.text[:200]}"}


def cek_paste(e164: str, api_key: str) -> dict:
    url = f"{HIBP_BASE}/breachedaccount/{quote(e164)}/paste"
    r = requests.get(url, headers=hibp_headers(api_key), timeout=30)
    if r.status_code == 200:
        return {"status": "ditemukan", "data": r.json()}
    if r.status_code == 404:
        return {"status": "bersih", "data": []}
    if r.status_code == 401:
        return {"status": "error", "data": "API key HIBP tidak valid atau tidak diset"}
    if r.status_code == 429:
        return {"status": "error", "data": "rate limit HIBP, coba lagi nanti"}
    return {"status": "error", "data": f"HTTP {r.status_code}"}


def format_breach(b: dict) -> str:
    tanggal = b.get("BreachDate", "?")
    nama = b.get("Name", "?")
    judul = b.get("Title", nama)
    dataclasses = ", ".join(b.get("DataClasses", [])) or "?"
    verif = "terverifikasi" if b.get("IsVerified") else "tidak terverifikasi"
    return f"  [{tanggal}] {judul} ({nama})\n    kelas data: {dataclasses}\n    status: {verif}"


def lapor(raw: str, api_key: str, json_output: bool = False) -> int:
    try:
        e164 = normalize(raw)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    operator = deteksi_operator(e164)
    result = cek_breach(e164, api_key)
    paste = cek_paste(e164, api_key)

    if json_output:
        print(json.dumps({
            "input": raw,
            "e164": e164,
            "operator": operator,
            "breach": result,
            "paste": paste,
        }, ensure_ascii=False, indent=2))
    else:
        print(f"Nomor   : {raw} -> {e164}")
        print(f"Operator: {operator}")
        print()
        if result["status"] == "bersih":
            print("Breach  : TIDAK ditemukan di basis data HIBP")
        elif result["status"] == "error":
            print(f"Breach  : ERROR - {result['data']}")
        else:
            breaches = result["data"]
            print(f"Brech   : DITEMUKAN di {len(breaches)} kebocoran:")
            for b in breaches:
                print(format_breach(b))
        print()
        if paste["status"] == "bersih":
            print("Paste   : tidak ditemukan di paste database HIBP")
        elif paste["status"] == "error":
            print(f"Paste   : ERROR - {paste['data']}")
        else:
            pastes = paste["data"]
            print(f"Paste   : DITEMUKAN di {len(pastes)} paste:")
            for p in pastes:
                sumber = p.get("Source") or p.get("Url", "?")
                print(f"  - {sumber} ({p.get('Date', 'tanpa tanggal')})")

    if result["status"] == "bocor" or paste["status"] == "ditemukan":
        return 1
    if result["status"] == "error":
        return 2
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Cek kebocoran data nomor telepon Indonesia via HIBP API"
    )
    ap.add_argument("nomor", nargs="+", help="nomor telepon (08xx / 628xx / +628xx)")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument(
        "--key",
        default=os.environ.get("HIBP_API_KEY", ""),
        help="API key Have I Been Pwned (atau set env HIBP_API_KEY)",
    )
    args = ap.parse_args()

    if not args.key:
        print(
            "ERROR: API key HIBP wajib. Daftar di https://haveibeenpwned.com/API/Key\n"
            "Set via env HIBP_API_KEY atau flag --key",
            file=sys.stderr,
        )
        sys.exit(2)

    kode = 0
    for n in args.nomor:
        k = lapor(n, args.key, args.json)
        if k > kode:
            kode = k
        if not args.json:
            print("\n" + "=" * 60 + "\n")
    sys.exit(kode)


if __name__ == "__main__":
    main()
