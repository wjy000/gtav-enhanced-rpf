"""CLI entry point: `python -m rpf_enhanced ...`

Supports the four most useful operations against GTA V Enhanced RPF7
archives: ``info``, ``list``, ``tree``, ``extract``, ``extract-keys``.
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

from .keys import GtaKeys
from .rpf import Archive, DirEntry, FileEntry


def _load_keys(args: argparse.Namespace) -> GtaKeys | None:
    if args.exe:
        print(f"[keys] extracting from {args.exe} ...", file=sys.stderr)
        return GtaKeys.from_enhanced_exe(args.exe)
    if args.aes_key:
        aes = Path(args.aes_key).read_bytes()
        print(f"[keys] deriving NG keys from {args.aes_key} ...", file=sys.stderr)
        return GtaKeys.from_aes_key(aes)
    if args.keys_dir:
        # CodeWalker-style pre-extracted files.
        d = Path(args.keys_dir)
        aes_key = (d / "gtav_aes_key.dat").read_bytes()
        # Reuse the same magic.dat derivation by skipping the AES scan;
        # the NG keys/tables in magic.dat are public and the same for
        # everyone, so we just regenerate them from the user's AES key.
        return GtaKeys.from_aes_key(aes_key)
    return None


def cmd_info(args: argparse.Namespace, keys: GtaKeys | None) -> int:
    arc = Archive(args.archive, keys=keys)
    enc_name = arc.encryption.name
    n_files = len(arc.list_files())
    n_dirs = sum(1 for e in arc.all_entries if isinstance(e, DirEntry))
    print(f"File       : {arc.path or arc.name}")
    print(f"Version    : {arc.version:#x} (RPF7)")
    print(f"Encryption : {enc_name}")
    print(f"Entries    : {arc.entry_count} ({n_dirs} dirs, {n_files} files)")
    return 0


def cmd_list(args: argparse.Namespace, keys: GtaKeys | None) -> int:
    arc = Archive(args.archive, keys=keys)
    files = arc.list_files()
    if args.pattern:
        files = [f for f in files if fnmatch.fnmatch(f.path, args.pattern)]
    for f in files:
        if args.detailed:
            kind = "res" if f.__class__.__name__ == "ResourceFileEntry" else "bin"
            print(f"{kind}  {f.file_size:>10}  {f.path}")
        else:
            print(f.path)
    print(f"\n{len(files)} file(s)", file=sys.stderr)
    return 0


def cmd_tree(args: argparse.Namespace, keys: GtaKeys | None) -> int:
    arc = Archive(args.archive, keys=keys)
    assert arc.root is not None
    _print_tree(arc.root, prefix="", depth=0, max_depth=args.depth)
    return 0


def _print_tree(d: DirEntry, prefix: str, depth: int, max_depth: int | None) -> None:
    print(f"{prefix}{d.name}/")
    child_prefix = prefix + "  "
    for f in d.files:
        print(f"{child_prefix}{f.name}")
    if max_depth is not None and depth >= max_depth:
        return
    for sub in d.directories:
        _print_tree(sub, child_prefix + "  ", depth + 1, max_depth)


def cmd_extract(args: argparse.Namespace, keys: GtaKeys | None) -> int:
    arc = Archive(args.archive, keys=keys)
    out = Path(args.output) if args.output else Path(Path(args.archive).stem)
    out.mkdir(parents=True, exist_ok=True)

    files = arc.list_files()
    if args.pattern:
        files = [f for f in files if fnmatch.fnmatch(f.path, args.pattern)]

    ok = fail = 0
    for i, f in enumerate(files, 1):
        dest = out / f.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = arc.extract(f)
            dest.write_bytes(data)
            ok += 1
            _progress(i, len(files), f.name)
        except Exception as exc:
            fail += 1
            print(f"\nfailed: {f.path}: {exc}", file=sys.stderr)
    print(f"\n\nextracted: {ok} / {len(files)}   failed: {fail}", file=sys.stderr)
    return 0 if fail == 0 else 1


def cmd_extract_keys(args: argparse.Namespace, _keys: GtaKeys | None) -> int:
    keys = GtaKeys.from_enhanced_exe(args.exe)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    keys.save(out)
    print(f"aes_key  = {keys.aes_key.hex()}")
    print(f"ng_keys  = {len(keys.ng_keys)} keys of {len(keys.ng_keys[0])} bytes each")
    print(f"tables   = 17 x 16 x 256 u32")
    print(f"saved to : {out}")
    return 0


def _progress(n: int, total: int, name: str) -> None:
    pct = n / total if total else 1.0
    bar = "=" * int(pct * 30)
    bar = bar.ljust(30)
    name = name if len(name) <= 37 else "..." + name[-37:]
    print(f"\r[{bar}] {n}/{total} {name:<40}", end="", flush=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rpf-enhanced",
        description="Read GTA V Enhanced RPF7 archives.",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--exe", help="Path to GTA5_Enhanced.exe (extract keys on the fly).")
    src.add_argument("--aes-key", help="Path to a 32-byte gtav_aes_key.dat file.")
    src.add_argument("--keys-dir", help="Directory containing gtav_aes_key.dat.")

    sub = p.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="Show archive metadata.")
    p_info.add_argument("archive")
    p_info.set_defaults(func=cmd_info)

    p_list = sub.add_parser("list", help="List file paths.")
    p_list.add_argument("archive")
    p_list.add_argument("pattern", nargs="?", default=None)
    p_list.add_argument("-d", "--detailed", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_tree = sub.add_parser("tree", help="Show archive contents as a tree.")
    p_tree.add_argument("archive")
    p_tree.add_argument("-d", "--depth", type=int, default=None)
    p_tree.set_defaults(func=cmd_tree)

    p_ext = sub.add_parser("extract", help="Extract all (or matched) files.")
    p_ext.add_argument("archive")
    p_ext.add_argument("-o", "--output", help="Output directory (default: archive stem).")
    p_ext.add_argument("pattern", nargs="?", default=None,
                       help="Optional glob, e.g. '*.xml'.")
    p_ext.set_defaults(func=cmd_extract)

    p_keys = sub.add_parser("extract-keys", help="Extract keys from GTA5_Enhanced.exe.")
    p_keys.add_argument("--exe", required=True, help="Path to GTA5_Enhanced.exe.")
    p_keys.add_argument("-o", "--output", required=True, help="Output directory.")
    p_keys.set_defaults(func=cmd_extract_keys)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    keys = _load_keys(args)
    return args.func(args, keys)


if __name__ == "__main__":
    raise SystemExit(main())
