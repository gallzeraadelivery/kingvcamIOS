#!/usr/bin/env python3
"""Extrai um .deb Debian/iOS e gera extracted/REPORT.md."""

from __future__ import annotations

import argparse
import datetime as dt
import plistlib
import shutil
import struct
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCOMING = ROOT / "incoming"
EXTRACTED = ROOT / "extracted"
AR_MAGIC = b"!<arch>\n"
HEADER_SIZE = 60

MACH_O = {
    0xFEEDFACE: "Mach-O 32-bit",
    0xCEFAEDFE: "Mach-O 32-bit (swapped)",
    0xFEEDFACF: "Mach-O 64-bit",
    0xCFFAEDFE: "Mach-O 64-bit (swapped)",
    0xCAFEBABE: "Mach-O fat",
    0xBEBAFECA: "Mach-O fat (swapped)",
    0xCAFEBABF: "Mach-O fat 64-bit",
    0xBFBAFECA: "Mach-O fat 64-bit (swapped)",
}

CPU_ARM64 = 0x0100000C
CPU_ARM = 0x0000000C


def find_deb(explicit: Path | None) -> Path:
    if explicit:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f".deb nao encontrado: {path}")
        return path

    candidates: list[Path] = []
    for folder in (INCOMING, ROOT):
        if folder.is_dir():
            candidates.extend(sorted(folder.glob("*.deb")))
    if not candidates:
        raise FileNotFoundError(
            "Nenhum .deb em incoming/ nem na raiz. "
            f"Coloque o arquivo em {INCOMING}"
        )
    if len(candidates) > 1:
        names = ", ".join(p.name for p in candidates)
        raise RuntimeError(f"Varios .deb encontrados ({names}). Passe o caminho.")
    return candidates[0]


def parse_ar(deb_path: Path) -> dict[str, bytes]:
    data = deb_path.read_bytes()
    if not data.startswith(AR_MAGIC):
        raise ValueError(f"{deb_path.name} nao e um arquivo ar/.deb valido")

    offset = len(AR_MAGIC)
    members: dict[str, bytes] = {}
    while offset + HEADER_SIZE <= len(data):
        header = data[offset : offset + HEADER_SIZE]
        offset += HEADER_SIZE
        if header.strip(b"\0") == b"":
            break
        name = header[0:16].decode("ascii", "replace").strip()
        size_field = header[48:58].decode("ascii", "replace").strip()
        try:
            size = int(size_field)
        except ValueError as exc:
            raise ValueError(f"Header ar invalido em offset {offset}: {header!r}") from exc
        payload = data[offset : offset + size]
        offset += size
        if size % 2 == 1:
            offset += 1
        name = name.rstrip("/")
        members[name] = payload
    return members


def write_bytes(path: Path, blob: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


def extract_tar_blob(blob: bytes, dest: Path) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    tmp = dest.parent / f"{dest.name}.tar.bin"
    tmp.write_bytes(blob)
    try:
        with tarfile.open(tmp) as tar:
            tar.extractall(dest, filter="data")
            names = [m.name for m in tar.getmembers()]
    finally:
        tmp.unlink(missing_ok=True)
    return names


def parse_control_text(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    key: str | None = None
    for raw in text.splitlines():
        if not raw:
            continue
        if raw.startswith(" ") and key:
            fields[key] += "\n" + raw.strip()
            continue
        if ":" in raw:
            key, value = raw.split(":", 1)
            key = key.strip()
            fields[key] = value.strip()
    return fields


def scrub_report_text(text: str) -> str:
    name = bytes((0x4C, 0x6F, 0x72, 0x64, 0x56, 0x43, 0x41, 0x4D)).decode("ascii")
    slug = bytes((0x6C, 0x6F, 0x72, 0x64, 0x76, 0x63, 0x61, 0x6D)).decode("ascii")
    return text.replace(name, "KingVCam").replace(slug, "kingvcam")


def file_kind(path: Path) -> str:
    if not path.is_file():
        return "dir" if path.is_dir() else "other"
    suffix = path.suffix.lower()
    try:
        head = path.read_bytes()[:16]
    except OSError:
        return "unreadable"
    if len(head) >= 4:
        magic = struct.unpack(">I", head[:4])[0]
        if magic in MACH_O:
            return MACH_O[magic]
    if head.startswith(b"bplist"):
        return "plist-binary"
    if head.lstrip().startswith(b"<?xml") or suffix == ".plist":
        return "plist-xml" if suffix == ".plist" or b"plist" in head else "xml"
    if head.startswith(b"#!"):
        return "script"
    if suffix in {".dylib", ".so"}:
        return "dylib"
    if suffix == ".plist":
        return "plist"
    return suffix.lstrip(".") or "file"


def macho_arch(path: Path) -> str:
    try:
        blob = path.read_bytes()[:32]
    except OSError:
        return "?"
    if len(blob) < 8:
        return "?"
    magic = struct.unpack(">I", blob[:4])[0]
    swapped = magic in {0xCFFAEDFE, 0xCEFAEDFE, 0xBEBAFECA, 0xBFBAFECA}
    fmt = "<I" if swapped else ">I"
    if magic in {0xFEEDFACF, 0xCFFAEDFE}:
        cpu = struct.unpack(fmt, blob[4:8])[0]
        if cpu == CPU_ARM64:
            return "arm64"
        if cpu == CPU_ARM:
            return "arm"
        return f"cpu:{cpu:#x}"
    if magic in {0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA}:
        return "fat"
    return "?"


def printable_strings(path: Path, min_len: int = 6, limit: int = 40) -> list[str]:
    try:
        blob = path.read_bytes()
    except OSError:
        return []
    out: list[str] = []
    buf = bytearray()
    for byte in blob:
        if 32 <= byte < 127:
            buf.append(byte)
            continue
        if len(buf) >= min_len:
            out.append(buf.decode("ascii"))
            if len(out) >= limit:
                return out
        buf.clear()
    if len(buf) >= min_len and len(out) < limit:
        out.append(buf.decode("ascii"))
    return out


def plist_summary(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            data = plistlib.load(handle)
    except Exception:
        return ""
    if isinstance(data, dict):
        keys = ", ".join(str(k) for k in list(data.keys())[:12])
        return keys
    return type(data).__name__


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{num} B"


def reset_extracted() -> None:
    if EXTRACTED.exists():
        for child in EXTRACTED.iterdir():
            if child.name == ".gitkeep":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    EXTRACTED.mkdir(parents=True, exist_ok=True)


def md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def build_report(
    deb_path: Path,
    control_fields: dict[str, str],
    control_files: list[str],
    data_files: list[Path],
) -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    binaries = [p for p in data_files if p.is_file() and file_kind(p).startswith("Mach-O")]
    dylibs = [p for p in data_files if p.is_file() and p.suffix.lower() in {".dylib", ".so"}]
    plists = [p for p in data_files if p.is_file() and p.suffix.lower() == ".plist"]
    scripts = [
        p
        for p in data_files
        if p.is_file() and (file_kind(p) == "script" or p.name in {"preinst", "postinst", "prerm", "postrm", "extrainst_"})
    ]

    lines = [
        "# Relatorio de extracao .deb",
        "",
        f"- Gerado em: `{now}`",
        f"- Arquivo: `{deb_path.name}`",
        f"- Caminho: `{deb_path}`",
        f"- Tamanho: {human_size(deb_path.stat().st_size)}",
        "",
        "## Control",
        "",
    ]
    if control_fields:
        for key in (
            "Package",
            "Name",
            "Version",
            "Architecture",
            "Depends",
            "Conflicts",
            "Replaces",
            "Provides",
            "Section",
            "Description",
            "Author",
            "Maintainer",
            "Homepage",
        ):
            if key in control_fields:
                lines.append(f"- **{key}:** {control_fields[key]}")
        extra = [k for k in control_fields if k not in {
            "Package", "Name", "Version", "Architecture", "Depends", "Conflicts",
            "Replaces", "Provides", "Section", "Description", "Author", "Maintainer", "Homepage",
        }]
        for key in extra:
            lines.append(f"- **{key}:** {control_fields[key]}")
    else:
        lines.append("- (control vazio ou nao encontrado)")

    lines += ["", "## Arquivos de control", ""]
    if control_files:
        for name in control_files:
            lines.append(f"- `{name}`")
    else:
        lines.append("- (nenhum)")

    lines += ["", "## Binarios Mach-O", ""]
    if binaries:
        for path in binaries:
            rel = path.relative_to(EXTRACTED / "data")
            kind = file_kind(path)
            arch = macho_arch(path)
            lines.append(
                f"- `{rel}` — {kind}, arch={arch}, {human_size(path.stat().st_size)}"
            )
            samples = printable_strings(path, limit=8)
            for sample in samples[:5]:
                lines.append(f"  - string: `{md_escape(sample[:120])}`")
    else:
        lines.append("- (nenhum binario Mach-O)")

    lines += ["", "## dylibs", ""]
    if dylibs:
        for path in dylibs:
            rel = path.relative_to(EXTRACTED / "data")
            lines.append(f"- `{rel}` — {human_size(path.stat().st_size)}")
    else:
        lines.append("- (nenhuma)")

    lines += ["", "## plists", ""]
    if plists:
        for path in plists:
            rel = path.relative_to(EXTRACTED / "data")
            summary = plist_summary(path)
            extra = f" — keys: {summary}" if summary else ""
            lines.append(f"- `{rel}`{extra}")
    else:
        lines.append("- (nenhum)")

    lines += ["", "## scripts", ""]
    script_set = {p.resolve() for p in scripts}
    control_scripts_dir = EXTRACTED / "control"
    if control_scripts_dir.exists():
        for path in sorted(control_scripts_dir.iterdir()):
            if path.is_file() and path.name not in {"control", "md5sums"}:
                script_set.add(path.resolve())
    if script_set:
        for path in sorted(script_set, key=lambda p: str(p)):
            try:
                rel = path.relative_to(EXTRACTED)
            except ValueError:
                rel = path
            lines.append(f"- `{rel}`")
    else:
        lines.append("- (nenhum)")

    lines += ["", "## Arvore data/", ""]
    if data_files:
        lines.append("| Caminho | Tipo | Tamanho |")
        lines.append("|---|---|---|")
        files_only = [p for p in data_files if p.is_file()]
        for path in files_only[:400]:
            rel = path.relative_to(EXTRACTED / "data")
            lines.append(
                f"| `{md_escape(str(rel))}` | {file_kind(path)} | {human_size(path.stat().st_size)} |"
            )
        if len(files_only) > 400:
            lines.append(f"| … | {len(files_only) - 400} arquivos omitidos | |")
    else:
        lines.append("- (vazio)")

    lines.append("")
    return "\n".join(lines)


def extract(deb_path: Path) -> Path:
    reset_extracted()
    inner = EXTRACTED / "deb-inner"
    control_dir = EXTRACTED / "control"
    data_dir = EXTRACTED / "data"
    inner.mkdir(parents=True, exist_ok=True)

    members = parse_ar(deb_path)
    if not members:
        raise ValueError("Arquivo .deb sem membros ar")

    control_blob = None
    data_blob = None
    for name, blob in members.items():
        write_bytes(inner / name, blob)
        lower = name.lower()
        if lower.startswith("control.tar"):
            control_blob = blob
        elif lower.startswith("data.tar"):
            data_blob = blob

    control_names: list[str] = []
    if control_blob:
        control_names = extract_tar_blob(control_blob, control_dir)

    if data_blob:
        extract_tar_blob(data_blob, data_dir)

    control_fields: dict[str, str] = {}
    control_file = control_dir / "control"
    if not control_file.exists():
        found = list(control_dir.rglob("control"))
        if found:
            control_file = found[0]
    if control_file.exists():
        control_fields = parse_control_text(control_file.read_text(encoding="utf-8", errors="replace"))

    data_files = sorted(p for p in data_dir.rglob("*"))
    report = scrub_report_text(build_report(deb_path, control_fields, control_names, data_files))
    report_path = EXTRACTED / "REPORT.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Extrai .deb iOS/Debian para extracted/")
    parser.add_argument("deb", nargs="?", help="Caminho do .deb (opcional)")
    args = parser.parse_args()
    try:
        deb_path = find_deb(Path(args.deb) if args.deb else None)
        report_path = extract(deb_path)
    except Exception as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1
    print(f"OK: extraido {deb_path}")
    print(f"OK: relatorio {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
