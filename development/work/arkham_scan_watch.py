import argparse
import ctypes
import struct
import sys
import time

from ue3_inspect import ProcessMemory, object_class_name, object_path


GOBJECTS = 0x026A1CA4
VK_X = 0x58
XINPUT_GAMEPAD_LEFT_SHOULDER = 0x0100


class XINPUT_GAMEPAD(ctypes.Structure):
    _fields_ = [
        ("wButtons", ctypes.c_ushort),
        ("bLeftTrigger", ctypes.c_ubyte),
        ("bRightTrigger", ctypes.c_ubyte),
        ("sThumbLX", ctypes.c_short),
        ("sThumbLY", ctypes.c_short),
        ("sThumbRX", ctypes.c_short),
        ("sThumbRY", ctypes.c_short),
    ]


class XINPUT_STATE(ctypes.Structure):
    _fields_ = [("dwPacketNumber", ctypes.c_ulong), ("Gamepad", XINPUT_GAMEPAD)]


def find_live(pm, class_name):
    data = pm.u32(GOBJECTS)
    count = pm.i32(GOBJECTS + 4) or 0
    result = []
    for index in range(count):
        obj = pm.u32(data + index * 4)
        if not obj or object_class_name(pm, obj) != class_name:
            continue
        path = object_path(pm, obj)
        if "Default__" not in path:
            result.append((obj, path))
    return result


def f32(pm, address):
    raw = pm.read(address, 4)
    return struct.unpack("<f", raw)[0] if len(raw) == 4 else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--seconds", type=float, default=30.0)
    args = parser.parse_args()

    pm = ProcessMemory(args.pid)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
    user32.GetAsyncKeyState.restype = ctypes.c_short

    xinput = None
    for dll_name in ("xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll"):
        try:
            xinput = ctypes.WinDLL(dll_name)
            xinput.XInputGetState.argtypes = [ctypes.c_ulong, ctypes.POINTER(XINPUT_STATE)]
            xinput.XInputGetState.restype = ctypes.c_ulong
            break
        except OSError:
            pass

    try:
        forensics = find_live(pm, "RForensicsDevice")
        scanners = find_live(pm, "RPhotoScanner")
        player_inputs = find_live(pm, "RPlayerInput")
        controllers = find_live(pm, "RPlayerControllerBm")
        if len(forensics) != 1:
            raise RuntimeError(f"Expected one live RForensicsDevice, found {forensics}")
        if len(scanners) != 1:
            raise RuntimeError(f"Expected one live RPhotoScanner, found {scanners}")
        if len(player_inputs) != 1:
            raise RuntimeError(f"Expected one live RPlayerInput, found {player_inputs}")
        if len(controllers) != 1:
            raise RuntimeError(f"Expected one live RPlayerControllerBm, found {controllers}")
        fd, fd_path = forensics[0]
        scanner, scanner_path = scanners[0]
        player_input, input_path = player_inputs[0]
        controller, controller_path = controllers[0]
        print(f"WATCHING forensics=0x{fd:08X} {fd_path}", flush=True)
        print(f"WATCHING scanner=0x{scanner:08X} {scanner_path}", flush=True)
        print(f"WATCHING input=0x{player_input:08X} {input_path}", flush=True)
        print(f"WATCHING controller=0x{controller:08X} {controller_path}", flush=True)
        print("NOW HOLD keyboard X, then controller LB, for about 3 seconds each.", flush=True)

        old = None
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            flags = pm.u32(fd + 0x220)
            state = XINPUT_STATE()
            pad_connected = bool(xinput and xinput.XInputGetState(0, ctypes.byref(state)) == 0)
            snapshot = (
                bool(user32.GetAsyncKeyState(VK_X) & 0x8000),
                pad_connected and bool(state.Gamepad.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER),
                flags,
                f32(pm, fd + 0x224),
                f32(pm, fd + 0x244),
                pm.u32(scanner + 0x1A8),
                f32(pm, scanner + 0x1E4),
                pm.u32(player_input + 0x184),
                pm.read(player_input + 0x188, 1)[0],
                pm.u32(controller + 0x67C),
                f32(pm, controller + 0x6EC),
            )
            # The final controller photo timer changes every frame. Ignore it
            # when deciding whether there is a meaningful input/scan change.
            comparison = snapshot[:-1]
            if comparison != old:
                print(
                    "X={} LB={} FD.flags=0x{:08X} scanRequested={} inScanMode={} "
                    "scanTimer={:.4f} power={:.4f} Photo.flags=0x{:08X} photoTimer={:.4f} "
                    "Input.flags=0x{:08X} leftShoulderAxis={} Controller.flags=0x{:08X} "
                    "lockForensics={} photoTimer={:.4f}".format(
                        snapshot[0], snapshot[1], snapshot[2] or 0,
                        bool((snapshot[2] or 0) & 0x4), bool((snapshot[2] or 0) & 0x8),
                        snapshot[3] or 0.0, snapshot[4] or 0.0,
                        snapshot[5] or 0, snapshot[6] or 0.0,
                        snapshot[7] or 0, snapshot[8],
                        snapshot[9] or 0, bool((snapshot[9] or 0) & 0x40), snapshot[10] or 0.0,
                    ),
                    flush=True,
                )
                old = comparison
            time.sleep(0.02)
        print("WATCH COMPLETE", flush=True)
    finally:
        pm.close()


if __name__ == "__main__":
    sys.exit(main())
