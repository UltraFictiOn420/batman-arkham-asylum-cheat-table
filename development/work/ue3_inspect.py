import argparse
import ctypes
import re
import struct
import sys
from ctypes import wintypes


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t


class ProcessMemory:
    def __init__(self, pid: int):
        self.handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            False,
            pid,
        )
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def read(self, address: int, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t()
        if not kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(got)
        ):
            return b""
        return buffer.raw[: got.value]

    def write(self, address: int, data: bytes):
        written = ctypes.c_size_t()
        buffer = ctypes.create_string_buffer(data)
        if not kernel32.WriteProcessMemory(
            self.handle,
            ctypes.c_void_p(address),
            buffer,
            len(data),
            ctypes.byref(written),
        ) or written.value != len(data):
            raise ctypes.WinError(ctypes.get_last_error())

    def u32(self, address: int):
        data = self.read(address, 4)
        return struct.unpack("<I", data)[0] if len(data) == 4 else None

    def i32(self, address: int):
        data = self.read(address, 4)
        return struct.unpack("<i", data)[0] if len(data) == 4 else None

    def regions(self):
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        max_address = 0x7FFF0000
        while address < max_address:
            result = kernel32.VirtualQueryEx(
                self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not result:
                address += 0x10000
                continue
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            if (
                mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_GUARD)
                and not (mbi.Protect & PAGE_NOACCESS)
            ):
                yield base, size, int(mbi.Protect), int(mbi.Type)
            next_address = base + max(size, 0x1000)
            address = next_address if next_address > address else address + 0x1000

    def scan(self, needle: bytes, alignment: int = 1, max_hits: int = 10000):
        hits = []
        overlap = max(len(needle) - 1, 0)
        for base, size, _protect, _kind in self.regions():
            offset = 0
            carry = b""
            while offset < size:
                chunk_size = min(0x100000, size - offset)
                data = self.read(base + offset, chunk_size)
                if not data:
                    break
                haystack = carry + data
                origin = base + offset - len(carry)
                start = 0
                while True:
                    found = haystack.find(needle, start)
                    if found < 0:
                        break
                    address = origin + found
                    if address % alignment == 0:
                        hits.append(address)
                        if len(hits) >= max_hits:
                            return hits
                    start = found + 1
                carry = haystack[-overlap:] if overlap else b""
                offset += len(data)
        return hits


def find_names(pm: ProcessMemory, term: str):
    raw = term.encode("ascii") + b"\0"
    hits = pm.scan(raw, max_hits=2000)
    print(f"ASCII {term!r}: {len(hits)} hit(s)")
    for address in hits[:200]:
        before = pm.read(max(address - 16, 0), 16)
        print(f"  0x{address:08X} before={before.hex(' ')}")


def find_gnames(pm: ProcessMemory):
    none_hits = pm.scan(b"None\0", max_hits=5000)
    entry_candidates = []
    for string_address in none_hits:
        for string_offset in (8, 12, 16):
            entry = string_address - string_offset
            index_values = [pm.i32(entry), pm.i32(entry + 4)]
            if 0 in index_values:
                entry_candidates.append((entry, string_offset, string_address))
    print(f"None strings={len(none_hits)} entry candidates={len(entry_candidates)}")
    seen = set()
    for entry, string_offset, string_address in entry_candidates:
        if entry in seen:
            continue
        seen.add(entry)
        pointer_hits = pm.scan(struct.pack("<I", entry), alignment=4, max_hits=20000)
        for pointer_address in pointer_hits:
            # A GNames data array generally begins with the None entry pointer.
            # Find structures that point to this pointer array and carry plausible Count/Max.
            array_pointer_hits = pm.scan(struct.pack("<I", pointer_address), alignment=4, max_hits=20000)
            for structure in array_pointer_hits:
                count = pm.i32(structure + 4)
                maximum = pm.i32(structure + 8)
                if count and maximum and 1000 < count <= maximum < 500000:
                    print(
                        f"GNAMES candidate struct=0x{structure:08X} data=0x{pointer_address:08X} "
                        f"count={count} max={maximum} noneEntry=0x{entry:08X} strOff={string_offset}"
                    )


GNAMES_STRUCT = 0x026A1C74
GNAMES_STRING_OFFSET = 16


def name_at(pm: ProcessMemory, index: int):
    data = pm.u32(GNAMES_STRUCT)
    count = pm.i32(GNAMES_STRUCT + 4)
    if not data or count is None or index < 0 or index >= count:
        return None
    entry = pm.u32(data + index * 4)
    if not entry:
        return None
    raw = pm.read(entry + GNAMES_STRING_OFFSET, 256)
    if not raw:
        return None
    return raw.split(b"\0", 1)[0].decode("latin1", errors="replace")


def dump_names(pm: ProcessMemory, pattern: str):
    regex = re.compile(pattern, re.IGNORECASE)
    count = pm.i32(GNAMES_STRUCT + 4) or 0
    matches = []
    for index in range(count):
        value = name_at(pm, index)
        if value and regex.search(value):
            matches.append((index, value))
    for index, value in matches:
        print(f"{index:6d} 0x{index:04X} {value}")
    print(f"MATCHES={len(matches)} NAMES={count}")


def find_gobjects(pm: ProcessMemory, module_base: int, module_size: int):
    module = pm.read(module_base, module_size)
    if len(module) != module_size:
        raise RuntimeError("Could not read the complete executable module")
    name_count = pm.i32(GNAMES_STRUCT + 4) or 0
    candidates = []
    for offset in range(0, len(module) - 12, 4):
        data, count, maximum = struct.unpack_from("<Iii", module, offset)
        if not (5000 <= count <= maximum <= 500000):
            continue
        sample = pm.read(data, min(count, 128) * 4)
        if len(sample) < 64:
            continue
        valid = 0
        named = 0
        classed = 0
        for item_offset in range(0, len(sample), 4):
            obj = struct.unpack_from("<I", sample, item_offset)[0]
            if obj == 0:
                continue
            header = pm.read(obj, 0x3C)
            if len(header) < 0x3C:
                continue
            vtable = struct.unpack_from("<I", header, 0)[0]
            if not (module_base <= vtable < module_base + module_size):
                continue
            valid += 1
            name_index = struct.unpack_from("<i", header, 0x20)[0]
            if 0 <= name_index < name_count:
                named += 1
            klass = struct.unpack_from("<I", header, 0x28)[0]
            if klass:
                class_header = pm.read(klass, 0x34)
                if len(class_header) >= 0x34:
                    class_name_index = struct.unpack_from("<i", class_header, 0x20)[0]
                    if 0 <= class_name_index < name_count:
                        classed += 1
        score = valid + named * 2 + classed * 2
        if valid >= 8 and named >= 8 and classed >= 8:
            candidates.append((score, module_base + offset, data, count, maximum, valid, named, classed))
    for candidate in sorted(candidates, reverse=True)[:40]:
        score, address, data, count, maximum, valid, named, classed = candidate
        print(
            f"GOBJECTS candidate struct=0x{address:08X} data=0x{data:08X} count={count} "
            f"max={maximum} score={score} sample(valid={valid},named={named},classed={classed})"
        )


def dump_objects(pm: ProcessMemory, gobjects_struct: int, pattern: str):
    regex = re.compile(pattern, re.IGNORECASE)
    data = pm.u32(gobjects_struct)
    count = pm.i32(gobjects_struct + 4) or 0
    matches = 0
    for index in range(count):
        obj = pm.u32(data + index * 4)
        if not obj:
            continue
        name_index = pm.i32(obj + 0x20)
        klass = pm.u32(obj + 0x28)
        class_name_index = pm.i32(klass + 0x20) if klass else None
        name = name_at(pm, name_index) if name_index is not None else None
        class_name = name_at(pm, class_name_index) if class_name_index is not None else None
        if regex.search((name or "") + " " + (class_name or "")):
            print(
                f"{index:6d} obj=0x{obj:08X} class={class_name!r} name={name!r} "
                f"path={object_path(pm, obj)!r}"
            )
            matches += 1
    print(f"MATCHES={matches} OBJECTS={count}")


def object_name(pm: ProcessMemory, obj: int):
    name_index = pm.i32(obj + 0x20)
    return name_at(pm, name_index) if name_index is not None else None


def object_class_name(pm: ProcessMemory, obj: int):
    klass = pm.u32(obj + 0x28)
    return object_name(pm, klass) if klass else None


def object_path(pm: ProcessMemory, obj: int, max_depth: int = 8):
    parts = []
    seen = set()
    current = obj
    for _ in range(max_depth):
        if not current or current in seen:
            break
        seen.add(current)
        parts.append(object_name(pm, current) or f"0x{current:08X}")
        current = pm.u32(current + 0x1C) or 0
    return ".".join(reversed(parts))


def dump_instances(pm: ProcessMemory, gobjects_struct: int, class_pattern: str):
    regex = re.compile(class_pattern, re.IGNORECASE)
    data = pm.u32(gobjects_struct)
    count = pm.i32(gobjects_struct + 4) or 0
    matches = 0
    for index in range(count):
        obj = pm.u32(data + index * 4)
        if not obj:
            continue
        class_name = object_class_name(pm, obj) or ""
        if regex.search(class_name):
            print(f"{index:6d} obj=0x{obj:08X} class={class_name!r} path={object_path(pm, obj)!r}")
            matches += 1
    print(f"MATCHES={matches} OBJECTS={count}")


def dump_properties(pm: ProcessMemory, gobjects_struct: int, property_pattern: str, owner_pattern: str):
    property_regex = re.compile(property_pattern, re.IGNORECASE)
    owner_regex = re.compile(owner_pattern, re.IGNORECASE)
    data = pm.u32(gobjects_struct)
    count = pm.i32(gobjects_struct + 4) or 0
    matches = 0
    for index in range(count):
        obj = pm.u32(data + index * 4)
        if not obj:
            continue
        class_name = object_class_name(pm, obj) or ""
        if not class_name.endswith("Property"):
            continue
        name = object_name(pm, obj) or ""
        owner = pm.u32(obj + 0x1C) or 0
        owner_name = object_name(pm, owner) or ""
        if not property_regex.search(name) or not owner_regex.search(owner_name):
            continue
        raw = pm.read(obj, 0x80)
        dwords = []
        for offset in range(0x2C, min(len(raw), 0x80), 4):
            value = struct.unpack_from('<I', raw, offset)[0]
            dwords.append(f"+{offset:02X}={value:08X}")
        print(
            f"{index:6d} obj=0x{obj:08X} type={class_name!r} owner={owner_name!r} "
            f"name={name!r} path={object_path(pm, obj)!r}\n  {' '.join(dwords)}"
        )
        matches += 1
    print(f"MATCHES={matches} OBJECTS={count}")


def probe_objects(pm: ProcessMemory, gobjects_struct: int, limit: int):
    data = pm.u32(gobjects_struct)
    count = pm.i32(gobjects_struct + 4) or 0
    shown = 0
    for index in range(count):
        obj = pm.u32(data + index * 4)
        if not obj:
            continue
        raw = pm.read(obj, 0x60)
        if len(raw) < 0x3C:
            continue
        print(f"INDEX={index} OBJ=0x{obj:08X}")
        for offset in range(0, 0x3C, 4):
            value = struct.unpack_from('<I', raw, offset)[0]
            possible_name = name_at(pm, value) if value < (pm.i32(GNAMES_STRUCT + 4) or 0) else None
            suffix = f" name={possible_name!r}" if possible_name else ""
            print(f"  +0x{offset:02X}=0x{value:08X}{suffix}")
        shown += 1
        if shown >= limit:
            break


def read_offsets(pm: ProcessMemory, address: int, offsets: str):
    print(f"OBJECT=0x{address:08X} class={object_class_name(pm, address)!r} path={object_path(pm, address)!r}")
    for token in offsets.split(','):
        offset = int(token.strip(), 0)
        raw = pm.read(address + offset, 12)
        if len(raw) < 4:
            print(f"  +0x{offset:X}: unreadable")
            continue
        u32 = struct.unpack_from('<I', raw, 0)[0]
        i32 = struct.unpack_from('<i', raw, 0)[0]
        f32 = struct.unpack_from('<f', raw, 0)[0]
        vec = struct.unpack_from('<fff', raw, 0) if len(raw) >= 12 else None
        print(f"  +0x{offset:X}: hex=0x{u32:08X} int={i32} float={f32:g} vec3={vec}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--find")
    parser.add_argument("--find-gnames", action="store_true")
    parser.add_argument("--names")
    parser.add_argument("--find-gobjects", action="store_true")
    parser.add_argument("--gobjects", type=lambda value: int(value, 0))
    parser.add_argument("--objects")
    parser.add_argument("--probe-objects", type=int)
    parser.add_argument("--instances")
    parser.add_argument("--properties")
    parser.add_argument("--owner", default=".*")
    parser.add_argument("--read", type=lambda value: int(value, 0))
    parser.add_argument("--offsets")
    parser.add_argument("--module-base", type=lambda value: int(value, 0), default=0x00400000)
    parser.add_argument("--module-size", type=lambda value: int(value, 0), default=0x026B3000)
    args = parser.parse_args()
    pm = ProcessMemory(args.pid)
    try:
        if args.find:
            find_names(pm, args.find)
        if args.find_gnames:
            find_gnames(pm)
        if args.names:
            dump_names(pm, args.names)
        if args.find_gobjects:
            find_gobjects(pm, args.module_base, args.module_size)
        if args.objects:
            if args.gobjects is None:
                parser.error("--objects requires --gobjects")
            dump_objects(pm, args.gobjects, args.objects)
        if args.probe_objects:
            if args.gobjects is None:
                parser.error("--probe-objects requires --gobjects")
            probe_objects(pm, args.gobjects, args.probe_objects)
        if args.instances:
            if args.gobjects is None:
                parser.error("--instances requires --gobjects")
            dump_instances(pm, args.gobjects, args.instances)
        if args.properties:
            if args.gobjects is None:
                parser.error("--properties requires --gobjects")
            dump_properties(pm, args.gobjects, args.properties, args.owner)
        if args.read is not None:
            if not args.offsets:
                parser.error("--read requires --offsets")
            read_offsets(pm, args.read, args.offsets)
    finally:
        pm.close()


if __name__ == "__main__":
    main()
