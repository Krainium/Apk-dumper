# APK Dumper

A Python script that rips every URL, hostname, REST endpoint out of an Android app package. Point it at an `.apk`, `.apkm`, `.xapk`, or `.aab` file. Get back a sorted text report of every network target the app references.

## Aim

When you reverse engineer an Android app, the first thing you usually want to know is what servers it talks to. Opening a disassembler for that is overkill. This script walks the entire archive as raw bytes looking for anything that looks like a URL or an API path, then writes you a clean report. Use it for OSINT on suspicious apps, for mapping the API surface of an app you're testing, or as a quick sanity check before you commit to a deeper dive.

## What it pulls

Everything the archive stores in plain text:

- Full URLs (`http`, `https`, `ws`, `wss`, `ftp`)
- URLs with raw IP literals like `http://127.0.0.1:8787/foo`
- Bare hostnames like `api.example.com/path`
- Relative REST paths like `/v1/users`, `/api/playlists/123`, `/oauth/token`
- A de-duplicated list of unique domains derived from all of the above

## Where it looks

- DEX bytecode (all string tables)
- Android resources and binary XML (including the manifest)
- The `assets/` folder (JS bundles, JSON configs, HTML, whatever is in there)
- Native libraries in `lib/` scanned as raw bytes
- Nested split APKs inside `.apkm` and `.xapk` bundles (it recurses one level deep)

## Requirements

- Python 3.8 or newer
- No third-party packages. The script uses only the standard library.

## Install

```bash
git clone https://github.com/krainium/apk-dumper.git
cd apk-dumper
chmod +x apk_dump.py
```

If you want to call it from anywhere:

```bash
sudo ln -s "$(pwd)/apk_dump.py" /usr/local/bin/apk-dump
```

## Usage

```bash
python3 apk_dump.py <path-to-app.apk>
```

With a custom output path:

```bash
python3 apk_dump.py myapp.apk -o myapp-urls.txt
```

If you skip `-o` the report lands next to the input file as `<filename>.urls.txt`.

### Flag reference

| Flag | Alias | Description |
|------|-------|-------------|
| positional | | Path to the `.apk` / `.apkm` / `.xapk` / `.aab` file |
| `--output <FILE>` | `-o` | Output path for the report. Defaults to `<input>.urls.txt` |
| `--help` | `-h` | Show help |

## Example

```bash
$ python3 apk_dump.py com.example.app.apk
[*] Scanning /home/me/com.example.app.apk (42.7 MB)...
[+] Wrote /home/me/com.example.app.apk.urls.txt
    URLs=186  hosts=94  endpoints=312
```

## Report layout

The output file is plain text split into sections:

```
# APK URL / Endpoint Dump
# Source  : /path/to/app.apk
# Entries : 847 scanned
# URLs    : 186
# Hosts   : 94
# Endpts  : 312
# Domains : 58

## Unique Domains
api.example.com
cdn.example.com
...

## Full URLs (http / https / ws / wss / ftp)
https://api.example.com/v2/login
...

## Bare Hosts / Unschemed URLs
analytics.example.net/track
...

## Relative API Endpoint Paths
/api/v1/users
/auth/token
...
```

The `Unique Domains` section is usually the first thing you want. Skim it to see who the app is talking to before you dig into the rest.

## How it works

The script opens the archive as a zip, walks every file, extracts printable ASCII runs from the raw bytes, then runs three regex passes on each run:

1. Full URL match on any `http/https/ws/wss/ftp` scheme
2. Bare host match on anything shaped like `label.label.tld`
3. REST path match on common prefixes like `/api`, `/v1`, `/auth`, `/graphql`, `/oauth`

Matches then go through a cleaning pass that:

- Trims trailing punctuation like `.`, `)`, `]`, `"`, backticks
- Balances stray parentheses
- Drops strings that look like Java package names (`com.google.android.foo.Bar`)
- Rejects mixed-case hosts because real URLs in apps are almost always lowercase
- Rejects hosts whose first label is a single character (a common DEX string table artifact)
- Filters against a closed list of valid TLDs to keep DEX garbage out of the results

If you need to tune the filtering, edit the `VALID_TLDS` set or the `NOISE_HOSTS` set near the top of the file. Both are commented.

## Limitations

- Strings encrypted or obfuscated at runtime will not show up. The script only sees what is stored in plain text.
- URLs built by concatenation at runtime (`BASE_URL + "/" + endpoint`) will appear as fragments rather than complete URLs.
- Native `.so` libraries can produce false positives. The TLD filter catches most of them but not all.
- The TLD list is closed on purpose to keep noise down. If an app uses a rare TLD you will need to add it to `VALID_TLDS`.
- Nested recursion is one level deep. An APKM containing APKs is fine. An APK inside an APK inside an APK is not.

## Notes

- Big APKs (a few hundred MB) take a few seconds. The bottleneck is regex scanning native libraries.
- The script never makes a network request. Everything runs locally on the file you give it.
- Output is sorted and de-duplicated so diffing two dumps of different app versions is easy.

## Contributing

Issues and pull requests welcome at https://github.com/krainium/apk-dumper. If you hit a false positive or a missed URL on a real app, open an issue with the APK name so I can reproduce.
