"""RPF7 archive reader.

Mirrors CodeWalker's `RpfFile.ReadHeader` from
`CodeWalker.Core/GameFiles/RpfFile.cs`. Only the read path is
implemented, and only the encryption modes used by GTA V Enhanced
(NG / TFIT, plus OPEN for nested modded archives).

Directory entry layout (16 bytes):
    u32 name_offset
    u32 ident        (== 0x7FFFFF00)
    u32 entries_index
    u32 entries_count

Binary file entry (16 bytes):
    u16 name_offset
    u24 file_size
    u24 file_offset
    u32 uncompressed_size
    u32 encryption_type   (0 = none, 1 = encrypted)

Resource file entry (16 bytes):
    u16 name_offset
    u24 file_size
    u24 file_offset       (top bit set: 0x800000 family)
    u32 system_flags
    u32 graphics_flags
"""

from __future__ import annotations

import enum
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from Crypto.Cipher import AES

from .crypto import decrypt_ng, get_ng_key_index
from .keys import GtaKeys

RPF_VERSION = 0x52504637   # "RPF7"

DIR_IDENT = 0x7FFFFF00


class Encryption(enum.IntEnum):
    NONE = 0x04E45504F           # "OPEN"
    AES = 0x0FFFFFF9
    NG = 0x0FFFFFFE              # displayed as 0xFEFFFFF in little-endian dumps
    DEFAULT = 0x0FFFFFFF


@dataclass
class Entry:
    name: str
    path: str
    name_offset: int
    field_h1: int
    field_h2: int


@dataclass
class DirEntry(Entry):
    entries_index: int
    entries_count: int
    directories: list["DirEntry"] = field(default_factory=list)
    files: list["FileEntry"] = field(default_factory=list)


@dataclass
class FileEntry(Entry):
    file_offset: int
    file_size: int
    is_encrypted: bool


@dataclass
class BinaryFileEntry(FileEntry):
    file_uncompressed_size: int
    encryption_type: int


@dataclass
class ResourceFileEntry(FileEntry):
    system_flags: int
    graphics_flags: int


class Archive:
    """An open RPF7 archive. Reads the header eagerly, file data lazily."""

    def __init__(self, path: str | Path, keys: GtaKeys | None = None,
                 data: bytes | None = None, name: str | None = None,
                 start: int = 0, file_size: int | None = None) -> None:
        self.path = Path(path) if not data else None
        self.name = name or (self.path.name if self.path else "memory")
        self.keys = keys
        self.start = start
        self.file_size = file_size if file_size is not None else (
            len(data) if data is not None else self.path.stat().st_size
        )

        if data is not None:
            self._data = data
        else:
            with open(self.path, "rb") as f:
                self._data = f.read()

        self.version: int = 0
        self.entry_count: int = 0
        self.names_length: int = 0
        self.encryption: Encryption = Encryption.NONE
        self.is_ng = False
        self.is_aes = False
        self.root: DirEntry | None = None
        self.all_entries: list[Entry] = []

        self._read_header()

    # ------------------------------------------------------------------ #
    # Header / TOC                                                       #
    # ------------------------------------------------------------------ #
    def _read_header(self) -> None:
        d = self._data
        off = self.start
        version, entry_count, names_length, enc_raw = struct.unpack_from("<IIII", d, off)
        off += 16

        if version != RPF_VERSION:
            raise ValueError(f"Not an RPF7 archive (magic={version:#x})")

        self.version = version
        self.entry_count = entry_count
        self.names_length = names_length
        try:
            self.encryption = Encryption(enc_raw)
        except ValueError:
            # Some modded/Enhanced archives use bare 0xFEFFFFF (LE) which
            # the enum doesn't catch; treat anything non-OPEN as NG.
            self.encryption = Encryption.NG if enc_raw != 0x04E45504F else Encryption.NONE

        entries_blob = d[off:off + entry_count * 16]
        off += entry_count * 16
        names_blob = d[off:off + names_length]

        if self.encryption == Encryption.AES:
            entries_blob = _decrypt_aes_ecb(entries_blob, self.keys)
            names_blob = _decrypt_aes_ecb(names_blob, self.keys)
            self.is_aes = True
        elif self.encryption == Encryption.NG:
            # CodeWalker passes the archive *file size* as the length seed.
            entries_blob = decrypt_ng(entries_blob, self.keys, self.name, self.file_size)
            names_blob = decrypt_ng(names_blob, self.keys, self.name, self.file_size)
            self.is_ng = True

        self._parse_entries(entries_blob, names_blob)
        self._build_tree()

    def _parse_entries(self, entries: bytes, names: bytes) -> None:
        for i in range(self.entry_count):
            base = i * 16
            y = struct.unpack_from("<I", entries, base)[0]
            x = struct.unpack_from("<I", entries, base + 4)[0]

            if x == 0x7FFFFF00:
                name_offset, _ident, entries_index, entries_count = struct.unpack_from(
                    "<IIII", entries, base
                )
                name = _read_cstring(names, name_offset)
                entry: Entry = DirEntry(
                    name=name, path=name, name_offset=name_offset,
                    field_h1=y, field_h2=x,
                    entries_index=entries_index, entries_count=entries_count,
                )
            elif (x & 0x80000000) == 0:
                # Binary file entry.
                buf = struct.unpack_from("<Q", entries, base)[0]
                name_offset = buf & 0xFFFF
                file_size = (buf >> 16) & 0xFFFFFF
                file_offset = (buf >> 40) & 0xFFFFFF
                uncompressed, enc_type = struct.unpack_from("<II", entries, base + 8)
                name = _read_cstring(names, name_offset)
                entry = BinaryFileEntry(
                    name=name, path=name, name_offset=name_offset,
                    field_h1=y, field_h2=x,
                    file_offset=file_offset, file_size=file_size,
                    is_encrypted=(enc_type == 1),
                    file_uncompressed_size=uncompressed,
                    encryption_type=enc_type,
                )
            else:
                # Resource file entry.
                name_offset = struct.unpack_from("<H", entries, base)[0]
                file_size = (
                    entries[base + 2]
                    | (entries[base + 3] << 8)
                    | (entries[base + 4] << 16)
                )
                file_offset = (
                    (entries[base + 5]
                     | (entries[base + 6] << 8)
                     | (entries[base + 7] << 16)) & 0x7FFFFF
                )
                system_flags, graphics_flags = struct.unpack_from("<II", entries, base + 8)
                name = _read_cstring(names, name_offset)
                entry = ResourceFileEntry(
                    name=name, path=name, name_offset=name_offset,
                    field_h1=y, field_h2=x,
                    file_offset=file_offset, file_size=file_size,
                    is_encrypted=False,
                    system_flags=system_flags, graphics_flags=graphics_flags,
                )

            self.all_entries.append(entry)

    def _build_tree(self) -> None:
        if not self.all_entries or not isinstance(self.all_entries[0], DirEntry):
            raise ValueError("RPF root entry is not a directory")
        root = self.all_entries[0]
        root.path = self.name.lower()
        self.root = root
        stack = [root]
        while stack:
            item = stack.pop()
            start = item.entries_index
            end = item.entries_index + item.entries_count
            for i in range(start, end):
                e = self.all_entries[i]
                if isinstance(e, DirEntry):
                    e.path = f"{item.path}/{e.name.lower()}"
                    item.directories.append(e)
                    stack.append(e)
                elif isinstance(e, FileEntry):
                    e.path = f"{item.path}/{e.name.lower()}"
                    item.files.append(e)

    # ------------------------------------------------------------------ #
    # Extraction                                                         #
    # ------------------------------------------------------------------ #
    def list_files(self) -> list[FileEntry]:
        result: list[FileEntry] = []
        assert self.root is not None
        stack = [self.root]
        while stack:
            d = stack.pop()
            result.extend(d.files)
            stack.extend(d.directories)
        return result

    def find_file(self, full_path: str) -> FileEntry | None:
        for f in self.list_files():
            if f.path == full_path or f.path.endswith("/" + full_path):
                return f
        return None

    def extract(self, entry: FileEntry) -> bytes:
        abs_off = self.start + entry.file_offset * 512
        if isinstance(entry, ResourceFileEntry):
            return self._extract_resource(entry, abs_off)
        return self._extract_binary(entry, abs_off)

    def _extract_binary(self, entry: BinaryFileEntry, abs_off: int) -> bytes:
        size = entry.file_size if entry.file_size else entry.file_uncompressed_size
        raw = self._data[abs_off:abs_off + size]
        if entry.is_encrypted:
            if self.is_aes:
                raw = _decrypt_aes_ecb(raw, self.keys)
            else:
                raw = decrypt_ng(raw, self.keys, entry.name, entry.file_uncompressed_size)
        if entry.file_size > 0:   # CodeWalker: FileSize>0 means it's DEFLATE-compressed
            try:
                raw = zlib.decompress(raw, -15)
            except zlib.error:
                pass
        return raw

    def _extract_resource(self, entry: ResourceFileEntry, abs_off: int) -> bytes:
        # First 0x10 bytes are an RSC7 header we skip; the rest is the payload.
        offset = 0x10
        if entry.file_size <= offset:
            return b""
        totlen = entry.file_size - offset
        raw = self._data[abs_off + offset:abs_off + offset + totlen]
        if entry.is_encrypted:
            if self.is_aes:
                raw = _decrypt_aes_ecb(raw, self.keys)
            else:
                raw = decrypt_ng(raw, self.keys, entry.name, entry.file_size)
        try:
            raw = zlib.decompress(raw, -15)
        except zlib.error:
            pass
        return raw

    def extract_nested(self, entry: BinaryFileEntry) -> "Archive | None":
        """If `entry` is a nested `.rpf`, parse and return it."""
        if not entry.name.lower().endswith(".rpf"):
            return None
        data = self.extract(entry)
        try:
            return Archive(
                path=entry.path, keys=self.keys, data=data,
                name=entry.name, start=0, file_size=len(data),
            )
        except Exception:
            return None


def _decrypt_aes_ecb(data: bytes, keys: GtaKeys | None) -> bytes:
    if keys is None:
        raise ValueError("AES-encrypted archive but no keys provided")
    return AES.new(keys.aes_key, AES.MODE_ECB).decrypt(data)


def _read_cstring(names: bytes, offset: int) -> str:
    end = names.find(b"\x00", offset)
    if end < 0:
        end = len(names)
    return names[offset:end].decode("latin-1", errors="replace")
