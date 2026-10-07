import argparse
import struct

from ue3_inspect import ProcessMemory, name_at


GNAMES = 0x026A1C74


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--input", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--match", default="")
    parser.add_argument("--key")
    parser.add_argument("--index", type=int)
    parser.add_argument("--replace")
    args = parser.parse_args()

    pm = ProcessMemory(args.pid)
    try:
        data = pm.u32(args.input + 0x60) or 0
        count = pm.i32(args.input + 0x64) or 0
        for index in range(count):
            entry = data + index * 0x18
            name_index = pm.i32(entry)
            name_number = pm.i32(entry + 4)
            command_data = pm.u32(entry + 8) or 0
            command_count = pm.i32(entry + 12) or 0
            command = ""
            if command_data and 0 < command_count < 4096:
                raw = pm.read(command_data, command_count * 2)
                command = raw.decode("utf-16-le", errors="replace").rstrip("\0")
            name = name_at(pm, name_index) or f"#{name_index}"
            if name_number:
                name = f"{name}_{name_number - 1}"
            text = f"{name} {command}"
            if (
                (args.index is None or index == args.index)
                and (args.key is None or name.lower() == args.key.lower())
                and args.match.lower() in text.lower()
            ):
                flags = pm.u32(entry + 0x14) or 0
                print(
                    f"[{index:03d}] entry=0x{entry:08X} name={name!r} "
                    f"command={command!r} flags=0x{flags:08X}"
                )
                if args.replace is not None:
                    encoded = (args.replace + "\0").encode("utf-16-le")
                    maximum = pm.i32(entry + 0x10) or 0
                    if len(encoded) // 2 > maximum:
                        raise RuntimeError(
                            f"Replacement needs {len(encoded) // 2} characters; capacity is {maximum}"
                        )
                    pm.write(command_data, encoded)
                    pm.write(entry + 0x0C, struct.pack("<i", len(encoded) // 2))
                    print(f"      replaced command with {args.replace!r}")
    finally:
        pm.close()


if __name__ == "__main__":
    main()
