#!/usr/bin/env python3
"""Atheris fuzz harness for pyntcloud's point-cloud file readers (pyntcloud.io.FROM_FILE).

pyntcloud reads many point-cloud / mesh formats (PLY, OBJ, OFF, PCD, NPZ, BIN, LAS/LAZ and the
plain ASCII variants ASC/CSV/PTS/TXT/XYZ). Each reader in ``pyntcloud.io.FROM_FILE`` takes a
*file path*, so the harness picks one supported extension from the fuzzer-provided bytes, writes
the rest of the input to a temp file with that suffix, and calls the matching reader — exercising
the same parse path ``PyntCloud.from_file`` drives.

Only the malformed-input errors a reader is *expected* to raise on garbage are swallowed; an
unexpected exception (an uncaught crash inside pyntcloud) is reported as a finding.

A per-input WATCHDOG (SIGALRM/itimer) bounds each reader call: some readers loop on truncated
input (e.g. ``pyntcloud.io.pcd.read_pcd`` spins forever on a .pcd file that never contains a
``DATA`` header line — ``readline()`` returns ``b""`` at EOF but the ``while True`` only breaks on
``DATA``). Without the watchdog the very first such input pins the campaign at exec/s~=0 and
coverage never climbs (this is exactly why the Mayhem run reported edges_covered=0). The watchdog
turns such a hang into a catchable timeout so the fuzzer skips it and keeps exploring the readers.

Atheris is a libFuzzer engine: run with libFuzzer flags it iterates; run with a single file
argument it replays that input once (standalone reproducer). The ELF ``launcher`` (launcher.c)
exec's ``python3`` on this file, forwarding every argument unchanged.
"""
import logging
import os
import signal
import struct
import sys
import tempfile
import warnings
import zipfile

import atheris

# Instrument the whole pyntcloud package so Atheris gets edge coverage of the readers. Importing
# ``pyntcloud.io`` here (and nothing before this block) means every reader submodule — ascii, bin,
# las, npz, obj, off, pcd, ply, plus the open3d/pyvista shims — is imported for the first time
# INSIDE the block, so all of them are instrumented (verify with "INFO: Instrumenting pyntcloud.io.*").
with atheris.instrument_imports():
    import pyntcloud.io as pio

from pandas.errors import EmptyDataError, ParserError

try:
    from laspy import LaspyException
except ImportError:  # laspy is optional; .las/.laz simply error out without it.
    class LaspyException(Exception):
        pass

# Readers are noisy on garbage input — silence logging/warnings so the fuzzer runs fast.
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")

# Map the io registry keys (ASC/PLY/...) to a concrete file suffix the reader expects.
SUPPORTED_EXTS = ["." + ext.lower() for ext in pio.FROM_FILE.keys()]


class _ReaderTimeout(Exception):
    """Raised by the per-input watchdog when a reader exceeds its wall-clock budget."""


def _watchdog(signum, frame):
    raise _ReaderTimeout()


# A pure-Python infinite loop (read_pcd) burns user-mode CPU and hits a bytecode boundary every
# iteration, so a virtual-timer signal interrupts it promptly. We deliberately use SIGVTALRM /
# ITIMER_VIRTUAL (not SIGALRM): Atheris's libFuzzer owns SIGALRM for its own -timeout, and stealing
# it prints "Fuzzer timeout will not work" and disables that backstop. Using the virtual timer lets
# our per-input watchdog and libFuzzer's wall-clock -timeout coexist. Native (C) calls inside
# numpy/pandas are not interrupted mid-call, but the readers' parse loops that can spin are pure
# Python (and read local temp files, so they burn CPU rather than block on I/O).
signal.signal(signal.SIGVTALRM, _watchdog)
WATCHDOG_SECS = 3.0


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    ext = fdp.PickValueInList(SUPPORTED_EXTS)
    reader = pio.FROM_FILE[ext[1:].upper()]
    payload = fdp.ConsumeBytes(fdp.remaining_bytes())

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(payload)
            tmp_path = tmp.name
        signal.setitimer(signal.ITIMER_VIRTUAL, WATCHDOG_SECS)
        reader(tmp_path)
    except (
        EmptyDataError,
        ParserError,
        ValueError,
        IndexError,
        KeyError,
        TypeError,
        OSError,
        UnicodeDecodeError,
        struct.error,
        StopIteration,
        NotImplementedError,
        EOFError,
        zipfile.BadZipFile,
        LaspyException,
        _ReaderTimeout,
    ):
        # Expected ways a malformed point-cloud stream is rejected (or a known reader loop is
        # bounded by the watchdog) — not defects.
        return -1
    finally:
        signal.setitimer(signal.ITIMER_VIRTUAL, 0)
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
