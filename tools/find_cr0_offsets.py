#!/usr/bin/env python3
"""Locate required kstuff CR0-chain helper candidates in PS5 kernel ELFs.

The scanner only searches executable PT_LOAD segments.  It reports exact
virtual addresses and offsets relative to the first PT_LOAD segment following
the executable kernel text (the usual kdata anchor), or to --kdata-base when
supplied.  Results are static candidates: review the emitted disassembly and
test them before use.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct
import sys
from typing import Iterable, Iterator, NamedTuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM
except ImportError as exc:  # pragma: no cover - environment diagnostic
    raise SystemExit("capstone is required: python -m pip install capstone") from exc


PT_LOAD = 1
PF_X = 1
class Segment(NamedTuple):
    offset: int
    vaddr: int
    filesz: int
    flags: int
    data: bytes


class ElfImage:
    def __init__(self, data: bytes, source: str):
        self.data = data
        self.source = source
        if len(data) < 64 or data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if data[4] != 2 or data[5] != 1:
            raise ValueError("only little-endian ELF64 is supported")
        machine = struct.unpack_from("<H", data, 18)[0]
        if machine != 62:
            raise ValueError(f"expected x86-64 ELF (e_machine=62), got {machine}")

        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize = struct.unpack_from("<H", data, 54)[0]
        phnum = struct.unpack_from("<H", data, 56)[0]
        if phentsize < 56 or phoff + phentsize * phnum > len(data):
            raise ValueError("invalid program-header table")

        self.segments: list[Segment] = []
        for index in range(phnum):
            pos = phoff + index * phentsize
            p_type, flags, offset, vaddr, _paddr, filesz, _memsz, _align = \
                struct.unpack_from("<IIQQQQQQ", data, pos)
            if p_type != PT_LOAD or not filesz:
                continue
            # Several public kernel ELFs omit zero-filled/trailing bytes while
            # retaining the original p_filesz.  Keep the declared virtual
            # address for anchor inference and scan only bytes actually here.
            available = min(filesz, max(0, len(data) - offset))
            self.segments.append(
                Segment(offset, vaddr, available, flags,
                        data[offset:offset + available])
            )

        if not any(segment.flags & PF_X for segment in self.segments):
            raise ValueError("ELF has no executable PT_LOAD segment")

    def default_kdata_base(self) -> int:
        executable = sorted(
            (segment for segment in self.segments if segment.flags & PF_X),
            key=lambda segment: segment.vaddr,
        )
        text_end = max(segment.vaddr + segment.filesz for segment in executable)
        following = sorted(
            (segment.vaddr for segment in self.segments
             if not segment.flags & PF_X and segment.vaddr >= text_end)
        )
        if not following:
            raise ValueError("cannot infer kdata PT_LOAD; use --kdata-base")
        return following[0]

    def executable_segments(self) -> Iterable[Segment]:
        return (segment for segment in self.segments if segment.flags & PF_X)

    def bytes_at(self, address: int, size: int) -> bytes:
        for segment in self.segments:
            delta = address - segment.vaddr
            if 0 <= delta < segment.filesz:
                return segment.data[delta:delta + size]
        return b""


MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


def find_regex(image: ElfImage, pattern: bytes) -> list[int]:
    regex = re.compile(b"(?=(" + pattern + b"))", re.DOTALL)
    found: list[int] = []
    for segment in image.executable_segments():
        found.extend(segment.vaddr + match.start() for match in regex.finditer(segment.data))
    return sorted(found)


def instruction_text(image: ElfImage, address: int, size: int = 48,
                     count: int = 8) -> list[str]:
    result = []
    for insn in MD.disasm(image.bytes_at(address, size), address, count=count):
        operands = f" {insn.op_str}" if insn.op_str else ""
        result.append(f"0x{insn.address:016x}: {insn.mnemonic}{operands}")
    return result


def verify_clear_store(image: ElfImage, address: int) -> tuple[bool, list[str]]:
    """Follow the small straight-line/JMP gadget to MOV [RSI],RAX; RET."""
    if image.bytes_at(address, 4) != b"\x48\x83\xe0\xf7":
        return False, []

    trace: list[str] = []
    pc = address
    stored = False
    popped_rbp = False
    visited: set[int] = set()
    for _ in range(8):
        if pc in visited:
            return False, trace
        visited.add(pc)
        decoded = list(MD.disasm(image.bytes_at(pc, 16), pc, count=1))
        if not decoded:
            return False, trace
        insn = decoded[0]
        operands = f" {insn.op_str}" if insn.op_str else ""
        trace.append(f"0x{insn.address:016x}: {insn.mnemonic}{operands}")

        if pc == address:
            pc += insn.size
            continue
        if insn.mnemonic == "mov" and insn.op_str == "qword ptr [rsi], rax":
            stored = True
            pc += insn.size
            continue
        if insn.mnemonic == "pop" and insn.op_str == "rbp" and not popped_rbp:
            popped_rbp = True
            pc += insn.size
            continue
        if insn.mnemonic == "ret":
            return stored, trace
        if insn.mnemonic == "jmp" and len(insn.operands) == 1 \
                and insn.operands[0].type == X86_OP_IMM:
            pc = insn.operands[0].imm & ((1 << 64) - 1)
            continue
        return False, trace
    return False, trace


def find_clear_store(image: ElfImage) -> tuple[list[int], dict[int, list[str]]]:
    candidates = find_regex(image, rb"\x48\x83\xe0\xf7")
    traces: dict[int, list[str]] = {}
    accepted = []
    for address in candidates:
        valid, trace = verify_clear_store(image, address)
        if valid:
            accepted.append(address)
            traces[address] = trace
    return accepted, traces


def signed_hex(value: int) -> str:
    sign = "-" if value < 0 else ""
    return f"{sign}0x{abs(value):x}"


def candidate_record(image: ElfImage, addresses: list[int], kdata_base: int,
                     traces: dict[int, list[str]] | None = None) -> dict[str, object]:
    values = []
    for address in addresses:
        item: dict[str, object] = {
            "address": f"0x{address:016x}",
            "offset": address - kdata_base,
            "offset_hex": signed_hex(address - kdata_base),
            "disassembly": (traces or {}).get(address)
                or instruction_text(image, address),
        }
        values.append(item)
    return {
        "status": "unique" if len(values) == 1 else
                  "missing" if not values else "ambiguous",
        "selected": values[0] if values else None,
        "candidates": values,
    }


def analyze(data: bytes, source: str, forced_kdata_base: int | None) -> dict[str, object]:
    image = ElfImage(data, source)
    kdata_base = forced_kdata_base if forced_kdata_base is not None \
        else image.default_kdata_base()

    clear_store, clear_traces = find_clear_store(image)
    matches = {
        "cr0_load": (find_regex(image, rb"\x48\x8b\x47\x58(?:\x5d)?\xc3"), None),
        "cr0_clear_store": (clear_store, clear_traces),
        "cr0_write_ret": (find_regex(image, rb"\x0f\x22\xc0(?:\x5d)?\xc3"), None),
        "store_rax_rdi": (find_regex(image, rb"\x48\x89\x07(?:\x5d)?\xc3"), None),
    }
    helpers = {
        name: candidate_record(image, addresses, kdata_base, traces)
        for name, (addresses, traces) in matches.items()
    }
    complete = all(item["status"] == "unique" for item in helpers.values())
    has_all = all(item["status"] != "missing" for item in helpers.values())
    return {
        "source": source,
        "kdata_base": f"0x{kdata_base:016x}",
        "status": "complete" if complete else "needs-review",
        "has_all_helpers": has_all,
        "helpers": helpers,
    }


def iter_inputs(paths: list[Path]) -> Iterator[tuple[str, bytes]]:
    for path in paths:
        if path.is_dir():
            children = sorted(
                child for child in path.rglob("*")
                if child.is_file() and child.suffix.lower() == ".elf"
            )
            yield from iter_inputs(children)
            continue
        if not path.is_file():
            print(f"warning: input does not exist: {path}", file=sys.stderr)
            continue
        yield str(path), path.read_bytes()


def print_human(report: dict[str, object]) -> None:
    print(f"\n{report['source']}")
    print(f"  kdata_base = {report['kdata_base']}  [{report['status']}]")
    helpers = report["helpers"]
    assert isinstance(helpers, dict)
    for name, raw in helpers.items():
        item = raw
        assert isinstance(item, dict)
        candidates = item["candidates"]
        assert isinstance(candidates, list)
        print(f"  {name}: {item['status']} ({len(candidates)} candidate(s))")
        for index, candidate in enumerate(candidates):
            selected = "  [selected]" if index == 0 else ""
            print(f"    {candidate['address']}  {candidate['offset_hex']}{selected}")
    if report["has_all_helpers"]:
        label = "header definitions" if report["status"] == "complete" \
            else "candidate header definitions (review ambiguous selections)"
        print(f"  {label}:")
        for name, item in helpers.items():
            candidate = item["selected"]
            print(f"    DEF({name}, {candidate['offset_hex']})")


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "examples:\n"
            "  python tools/find_cr0_offsets.py C:\\kernels\\unpacked\n"
            "  python tools/find_cr0_offsets.py kernel_retail_250.elf --json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="+", type=Path,
                        help="ELF file or directory containing unpacked ELFs")
    parser.add_argument("--kdata-base", type=parse_int,
                        help="override the inferred PT_LOAD kdata anchor")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    reports = []
    failures = 0
    for source, data in iter_inputs(args.paths):
        try:
            reports.append(analyze(data, source, args.kdata_base))
        except (ValueError, struct.error) as exc:
            failures += 1
            print(f"warning: {source}: {exc}", file=sys.stderr)

    if args.json:
        json.dump(reports, sys.stdout, indent=2)
        print()
    else:
        for report in reports:
            print_human(report)
        print(f"\nScanned {len(reports)} ELF(s); {failures} failure(s).")

    return 1 if failures or any(not r["has_all_helpers"] for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
