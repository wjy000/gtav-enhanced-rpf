# rpf-enhanced

> 如需查看中文,请点击 [README_CN.md](README_CN.md)。

A small, dependency-light Python CLI for reading **GTA V Enhanced** (Gen9,
`GTA5_Enhanced.exe`) RPF7 archives. Built for modders who want a scriptable
alternative to CodeWalker on macOS / Linux.

> Not affiliated with Rockstar Games. Use only with legally obtained game
> files you own.

Only the **Enhanced** path is supported. For Legacy `GTA5.exe` support use
[CodeWalker](https://github.com/dexyfex/CodeWalker) or
[rpf-cli](https://github.com/VIRUXE/rpf-cli).

## Status

Works against real Enhanced archives (`update2.rpf`, `common.rpf`, …):

| Command        | Result |
|----------------|--------|
| `info`         | Parses header, encryption, entry counts ✓ |
| `list`         | Lists decrypted file paths, glob filter ✓ |
| `tree`         | Full directory tree ✓ |
| `extract`      | Writes files with correct content (verified `version.txt` → `1013.34-dev_gen9_sga_live`, `credits.ymt` → readable text) ✓ |
| `extract-keys` | Writes the three CodeWalker-compatible `.dat` files ✓ |

## Install

```sh
git clone <this repo>
cd rpf-enhanced
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt   # only pycryptodome
```

Requires Python 3.10+ (uses PEP 604 `X | Y` type hints).

## Quick start

```sh
# 1. Extract keys once (writes gtav_aes_key.dat + gtav_ng_key.dat + gtav_ng_decrypt_tables.dat)
.venv/bin/python -m rpf_enhanced extract-keys \
    --exe "/path/to/GTA5_Enhanced.exe" \
    -o keys/

# 2. Inspect an archive (re-extracts the AES key on the fly each time)
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" info  update2.rpf
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" list  update2.rpf
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" tree  update2.rpf

# 3. Extract everything (or a glob)
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" extract update2.rpf -o out/
.venv/bin/python -m rpf_enhanced --exe "/path/to/GTA5_Enhanced.exe" extract update2.rpf '*/version.txt'
```

### Avoiding the 52 MB exe scan every run

Once you've run `extract-keys`, reuse the saved 32-byte AES key — the NG
keys / tables are regenerated from `magic.dat` in milliseconds:

```sh
.venv/bin/python -m rpf_enhanced --aes-key keys/gtav_aes_key.dat extract update2.rpf -o out/
```

## Commands

| Subcommand     | Description |
|----------------|-------------|
| `info`         | Show archive metadata (version, encryption, entry counts). |
| `list [pattern]` | List file paths. Optional glob, e.g. `*.xml`. `-d` for detailed. |
| `tree [-d N]`  | Directory tree. `-d N` limits depth. |
| `extract [-o DIR] [pattern]` | Extract files. Pattern filters by glob. |
| `extract-keys --exe FILE -o DIR` | Extract keys from `GTA5_Enhanced.exe`. |

## Key sources

Three mutually-exclusive global flags select how keys are obtained:

| Flag           | Behaviour |
|----------------|-----------|
| `--exe PATH`   | SHA1-scan `GTA5_Enhanced.exe` for the AES key, then derive NG keys from `magic.dat`. |
| `--aes-key FILE` | Read a 32-byte `gtav_aes_key.dat`, derive NG keys from `magic.dat`. |
| `--keys-dir DIR` | Same as `--aes-key DIR/gtav_aes_key.dat` (CodeWalker-style dir). |

## How it works

All cryptographic steps are ported **line-for-line** from CodeWalker's
published C# source — no reverse-engineered or invented algorithms.
See [`ALGORITHM.md`](ALGORITHM.md) (in Chinese) for the full walkthrough:

1. Scan `GTA5_Enhanced.exe` for a 32-byte window whose SHA1 equals the
   public constant `PC_AES_KEY_HASH`. Result: per-user AES key.
2. Seed a .NET-compatible `System.Random` with
   `(int)JenkHash.GenHash(PC_AES_KEY)` and pull four byte streams `rb1..rb4`.
3. Deobfuscate the bundled `magic.dat` (154_069 B, SHA256
   `dc35981f822e892ced3aa81d31e7a96927d573ee28f67417592b5afeaf330832`):
   `db[i] = (magic[i] - rb1[i] - rb2[i] - rb3[i] - rb4[i]) & 0xFF`.
4. AES-256-ECB decrypt, then raw-DEFLATE inflate → 306_272 B containing
   the 101 NG keys + 17×16×256 decrypt tables (+ LUT + AWC key, unused).
5. Parse the RPF7 header, decrypt the NG-encrypted TOC with the TFIT
   block cipher, then read file payloads at their 512-byte-block offsets.

The bundled `magic.dat` is identical for Enhanced and Legacy; only the
AES key differs. Verified against
[Microsoft's official `Random(Int32)` test vectors](https://learn.microsoft.com/dotnet/api/system.random.-ctor).

## Project layout

```
rpf-enhanced/
├── README.md
├── ALGORITHM.md              # full algorithm walkthrough (Chinese)
├── requirements.txt          # pycryptodome
└── rpf_enhanced/
    ├── __main__.py           # entry: .venv/bin/python -m rpf_enhanced
    ├── cli.py                # argparse subcommands
    ├── dotnet_random.py      # .NET System.Random port
    ├── jenkhash.py           # Jenkins one-at-a-time hash
    ├── keys.py               # AES scan + magic.dat deobfuscation
    ├── crypto.py             # TFIT NG block cipher
    ├── rpf.py                # RPF7 parser
    └── magic.dat             # embedded encrypted key blob
```

## Credits

- [CodeWalker](https://github.com/dexyfex/CodeWalker) — primary reference
  implementation. Every algorithm here mirrors CodeWalker's C# code:
  - `GTAKeys.GenerateV2` / `UseMagicData` — key extraction
  - `GTACrypto.DecryptNG` / `DecryptNGBlock` — TFIT cipher (originally by Neodymium, MIT)
  - `RpfFile.ReadHeader` — RPF7 layout
  - `Resources/magic.dat` — embedded key blob
- [Microsoft .NET reference source](https://github.com/microsoft/referencesource)
  — `System.Random` (Knuth subtractive generator)
- [Swage](https://github.com/0x1F9F1/Swage) — independent C++ implementation,
  used to cross-check the TFIT structure
- [gtamods wiki](https://gtamods.com/wiki/RPF_archive) — RPF format reference

## License

MIT, matching CodeWalker's license. See `LICENSE`.
