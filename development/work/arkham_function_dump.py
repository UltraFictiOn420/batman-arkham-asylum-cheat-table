import argparse
import struct

from ue3_inspect import ProcessMemory, object_path


GOBJECTS = 0x026A1CA4


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--function", required=True, type=lambda value: int(value, 0))
    args = parser.parse_args()
    pm = ProcessMemory(args.pid)
    try:
        data = pm.u32(args.function + 0x48) or 0
        size = pm.i32(args.function + 0x4C) or 0
        raw = pm.read(data, size)
        print(f"script=0x{data:08X} size={size}")
        objects_data = pm.u32(GOBJECTS) or 0
        objects_count = pm.i32(GOBJECTS + 4) or 0
        objects = set()
        for index in range(objects_count):
            obj = pm.u32(objects_data + index * 4)
            if obj:
                objects.add(obj)
        for base in range(0, len(raw), 16):
            chunk = raw[base : base + 16]
            print(f"{base:04X}: {' '.join(f'{byte:02X}' for byte in chunk)}")
            for offset in range(base, min(base + 16, len(raw) - 3)):
                value = struct.unpack_from("<I", raw, offset)[0]
                if value in objects:
                    print(f"      +{offset:04X} -> 0x{value:08X} {object_path(pm, value)}")
    finally:
        pm.close()


if __name__ == "__main__":
    main()
