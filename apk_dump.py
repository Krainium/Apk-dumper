#!/usr/bin/env python3
"""
apk_url_dump.py — Extract every URL and API endpoint from an APK / APKM / XAPK / AAB.

Usage:
    python3 apk_url_dump.py <path-to-app.apk> [-o output.txt]

Scans all files inside the archive (DEX bytecode, resources, assets, native libs,
binary XML manifest, nested split APKs) for HTTP/HTTPS URLs and REST-style API
endpoint paths. Writes a sorted, de-duplicated report to a .txt file.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

# --- Regexes --------------------------------------------------------------

# A domain label: 1–63 chars, lowercase/digits/hyphens, cannot start/end with "-".
_LABEL = rb"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# A host: two or more labels separated by dots, last label is a letters-only TLD.
_HOST = rb"(?:" + _LABEL + rb"\.)+[a-z][a-z]{1,23}"
# Optional :port
_PORT = rb"(?::\d{1,5})?"
# Path/query/fragment chars (URL-safe). No whitespace/quotes/backticks.
_PATH = rb"(?:/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?"

# Full http(s) / ws(s) / ftp URLs
URL_RE = re.compile(
    rb"(?:https?|wss?|ftp)://" + _HOST + _PORT + _PATH,
    re.IGNORECASE,
)

# IP-literal URLs (e.g. http://127.0.0.1:8787/foo)
URL_IP_RE = re.compile(
    rb"(?:https?|wss?|ftp)://(?:\d{1,3}\.){3}\d{1,3}" + _PORT + _PATH,
    re.IGNORECASE,
)

# Bare hosts like api.example.com(/path). Must have a preceding non-identifier byte
# so we don't pick up the tail of Java package names (com.foo.bar.Class).
HOST_RE = re.compile(
    rb"(?<![A-Za-z0-9._-])" + _HOST + _PATH,
    re.IGNORECASE,
)

# Relative-looking REST endpoints: /v1/foo, /api/bar/baz
ENDPOINT_RE = re.compile(
    rb"(?<![A-Za-z0-9._/-])/(?:api|v\d+|rest|graphql|auth|oauth|login|logout|"
    rb"token|user|users|account|accounts|session|sessions|watch|upload|"
    rb"playlist|playlists|videos|video|channel|channels|search|feed|feeds|"
    rb"live|stream|streams|player|comment|comments|subscribe|subscriptions|"
    rb"notifications?|metrics|log|logs|config|configs|ad|ads|tracking)"
    rb"(?:/[A-Za-z0-9_\-.]+){0,6}",
    re.IGNORECASE,
)

# Printable-ASCII string extractor for DEX/binary files
PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")

# Junk we don't want in URL results
URL_TRAILING_TRIM = b".,;:!?)]}>\"'`"
# TLDs we accept. A closed list keeps DEX-concatenation garbage out while still
# catching the long tail. Add/remove as needed.
VALID_TLDS = {
    b"com", b"net", b"org", b"io", b"co", b"gov", b"edu", b"dev", b"app",
    b"ai", b"cloud", b"xyz", b"info", b"me", b"tv", b"us", b"uk", b"de",
    b"jp", b"cn", b"ru", b"br", b"fr", b"it", b"nl", b"es", b"ca", b"au",
    b"in", b"mx", b"sg", b"hk", b"kr", b"tw", b"eu", b"biz", b"tech", b"ly",
    b"to", b"gl", b"gg", b"is", b"se", b"no", b"fi", b"pl", b"cz", b"ch",
    b"at", b"be", b"pt", b"gr", b"tr", b"id", b"th", b"ph", b"vn", b"my",
    b"za", b"ng", b"ke", b"ar", b"cl", b"pe", b"ve", b"nz", b"ie", b"dk",
    b"ua", b"il", b"sa", b"ae", b"qa", b"hu", b"ro", b"sk", b"bg", b"hr",
    b"si", b"lt", b"lv", b"ee", b"rs", b"re", b"pro", b"site", b"online",
    b"store", b"shop", b"link", b"page", b"blog", b"news", b"media", b"live",
    b"run", b"inc", b"llc", b"ltd", b"name", b"mobi", b"asia", b"studio",
    b"agency", b"digital", b"cafe", b"games", b"fun", b"world", b"global",
    b"network", b"systems", b"solutions", b"services", b"group", b"company",
    b"center", b"zone", b"space", b"website", b"social", b"email", b"video",
    b"photo", b"audio", b"film", b"music", b"band", b"art", b"design",
    b"academy", b"school", b"review", b"reviews", b"guide", b"wiki", b"help",
    b"support", b"pub", b"bar", b"club", b"vip", b"top", b"best", b"new",
    b"one", b"sh", b"tk",
    # Intentionally omitted: cc (C++ source), ts (TypeScript), is (noisy).
}

NOISE_HOSTS = {
    b"example.com",
    b"schemas.android.com",
    b"www.w3.org",
    b"ns.adobe.com",
    b"xmlns.com",
    b"purl.org",
    b"www.youtube.com/",  # only when empty path junk
}


def _clean_url(raw: bytes) -> bytes:
    while raw and raw[-1:] in URL_TRAILING_TRIM:
        raw = raw[:-1]
    # balance unmatched trailing parens
    while raw.endswith(b")") and raw.count(b"(") < raw.count(b")"):
        raw = raw[:-1]
    return raw


def _decode(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1", errors="replace")


_JAVA_PKG_MARKERS = (
    b".google.android.", b".google.common.", b".google.protobuf.",
    b".googlecode.", b".kotlin.", b".kotlinx.", b".androidx.", b".java.",
    b".javax.", b".apache.", b".squareup.", b".jakewharton.",
    b"android.gms.", b"android.apps.", b"android.libraries.",
    b"com.google.", b"com.android.", b"com.youtube.", b"com.facebook.",
    b"org.chromium.", b"org.webrtc.", b"io.grpc.", b"io.netty.",
)

def _looks_like_java_pkg(host: bytes) -> bool:
    # DEX string tables concatenate class/package names that look like hosts
    # when they end on a TLD-ish token (com.foo.bar.app). Filter the obvious ones.
    if host.count(b".") > 4:
        return True
    low = host.lower()
    for marker in _JAVA_PKG_MARKERS:
        if marker in b"." + low + b".":
            return True
    # First label of 1 char followed by known package root (length-byte artifact):
    #   "1com.google..." "7type.googleapis.com" etc.
    if re.match(rb"^[0-9a-z](?:com|org|net|io|type|outputtype|videopresenter)\.", low):
        return True
    return False


def _tld_ok(host: bytes) -> bool:
    label = host.lower().split(b"/", 1)[0].rsplit(b".", 1)[-1]
    return label in VALID_TLDS


def scan_bytes(data: bytes, buckets: dict):
    for run in PRINTABLE_RUN.findall(data):
        for m in URL_RE.findall(run):
            m = _clean_url(m)
            rest = m.split(b"://", 1)[1] if b"://" in m else m
            if _tld_ok(rest):
                buckets["urls"].add(m)
        for m in URL_IP_RE.findall(run):
            buckets["urls"].add(_clean_url(m))
        for m in HOST_RE.findall(run):
            host = _clean_url(m)
            host_part_raw = host.split(b"/", 1)[0]
            host_part = host_part_raw.lower()
            if host_part in NOISE_HOSTS:
                continue
            if not _tld_ok(host):
                continue
            if re.match(rb"^\d+\.\d+", host):
                continue
            if _looks_like_java_pkg(host_part):
                continue
            # Real URLs embedded in app code are almost always written lowercase.
            # Reject mixed-case strings: they're DEX identifiers leaking through.
            if host_part_raw != host_part_raw.lower():
                continue
            # Reject things like "0.vn", "a.cl" — DEX concat artefacts where
            # the first label is 1 char. Real 1-char subdomains are vanishingly
            # rare and not worth the noise.
            first_label = host_part.split(b".", 1)[0]
            if len(first_label) < 2:
                continue
            buckets["hosts"].add(host)
        for m in ENDPOINT_RE.findall(run):
            buckets["endpoints"].add(m)


def iter_archive(path: Path):
    """Yield (entry_name, bytes) for every file inside an APK/APKM/XAPK/AAB."""
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        print(f"[!] Not a zip archive: {path}", file=sys.stderr)
        return
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                data = zf.read(info)
            except Exception as e:
                print(f"[!] Could not read {info.filename}: {e}", file=sys.stderr)
                continue
            yield info.filename, data
            # Recurse into nested APKs (APKM/XAPK bundles of split APKs)
            lower = info.filename.lower()
            if lower.endswith(".apk"):
                try:
                    nested = zipfile.ZipFile(io.BytesIO(data))
                except zipfile.BadZipFile:
                    continue
                with nested:
                    for ninfo in nested.infolist():
                        if ninfo.is_dir():
                            continue
                        try:
                            ndata = nested.read(ninfo)
                        except Exception:
                            continue
                        yield f"{info.filename}!{ninfo.filename}", ndata


def analyze(path: Path):
    buckets = {
        "urls": set(),
        "hosts": set(),
        "endpoints": set(),
    }
    per_file = defaultdict(int)
    total = 0
    for name, data in iter_archive(path):
        before = sum(len(v) for v in buckets.values())
        scan_bytes(data, buckets)
        after = sum(len(v) for v in buckets.values())
        per_file[name] = after - before
        total += 1
    return buckets, per_file, total


def write_report(path: Path, out: Path, buckets: dict, per_file: dict, total: int):
    urls = sorted({_decode(u) for u in buckets["urls"]}, key=str.lower)
    hosts = sorted({_decode(h) for h in buckets["hosts"]}, key=str.lower)
    endpoints = sorted({_decode(e) for e in buckets["endpoints"]}, key=str.lower)

    # Derive unique domains from urls+hosts for a quick-read section
    domain_re = re.compile(r"^(?:https?|wss?|ftp)://([^/:?#]+)", re.IGNORECASE)
    domains = set()
    for u in urls:
        m = domain_re.match(u)
        if m:
            domains.add(m.group(1).lower())
    for h in hosts:
        domains.add(h.split("/", 1)[0].lower())
    domains = sorted(domains)

    lines = []
    lines.append(f"# APK URL / Endpoint Dump")
    lines.append(f"# Source  : {path}")
    lines.append(f"# Entries : {total} scanned")
    lines.append(f"# URLs    : {len(urls)}")
    lines.append(f"# Hosts   : {len(hosts)}")
    lines.append(f"# Endpts  : {len(endpoints)}")
    lines.append(f"# Domains : {len(domains)}")
    lines.append("")

    lines.append("## Unique Domains")
    lines.extend(domains)
    lines.append("")

    lines.append("## Full URLs (http / https / ws / wss / ftp)")
    lines.extend(urls)
    lines.append("")

    lines.append("## Bare Hosts / Unschemed URLs")
    lines.extend(hosts)
    lines.append("")

    lines.append("## Relative API Endpoint Paths")
    lines.extend(endpoints)
    lines.append("")

    out.write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Dump all URLs / API endpoints from an APK.")
    ap.add_argument("apk", help="Path to .apk / .apkm / .xapk / .aab")
    ap.add_argument("-o", "--output", help="Output .txt (default: <apk-basename>.urls.txt)")
    args = ap.parse_args()

    path = Path(args.apk).expanduser().resolve()
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    out = Path(args.output).expanduser().resolve() if args.output \
        else path.with_suffix(path.suffix + ".urls.txt")

    print(f"[*] Scanning {path} ({path.stat().st_size / 1e6:.1f} MB)...")
    buckets, per_file, total = analyze(path)
    write_report(path, out, buckets, per_file, total)
    print(f"[+] Wrote {out}")
    print(f"    URLs={len(buckets['urls'])}  hosts={len(buckets['hosts'])}  endpoints={len(buckets['endpoints'])}")


if __name__ == "__main__":
    main()
