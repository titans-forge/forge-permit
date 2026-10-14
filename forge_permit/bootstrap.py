# SPDX-License-Identifier: Apache-2.0
"""Trusted bootstrap: install Seatbelt before reading any worker input."""
import ctypes
import json
import os
import socket
import sys


def main():
    profile, worker = sys.argv[1:]
    # Compile trusted fixture code before sandboxing; never evaluate caller-supplied code here.
    with open(worker, "rb") as handle:
        code = compile(handle.read(), worker, "exec")
    lib = ctypes.CDLL("/usr/lib/libsandbox.dylib")
    install = lib.sandbox_init
    install.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char_p)]
    install.restype = ctypes.c_int
    error = ctypes.c_char_p()
    if install(profile.encode(), 0, ctypes.byref(error)) != 0:
        raise RuntimeError("sandbox_install_failed")
    exec(code, {"__name__": "__main__", "__file__": worker})


if __name__ == "__main__":
    main()
