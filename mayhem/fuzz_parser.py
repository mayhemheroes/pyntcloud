#!/usr/bin/env python3
import atheris
import laspy
import logging
import sys
import tempfile

with atheris.instrument_imports(include=['pyntcloud', 'pyntcloud.core_class']):
    import pyntcloud.io as pio

from pandas.errors import EmptyDataError, ParserError

supported_exts = list(pio.FROM_FILE.keys())

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    fuzz_ext = fdp.PickValueInList(supported_exts)
    fuzz_func = pio.FROM_FILE[fuzz_ext]
    fuzz_data = fdp.ConsumeBytes(fdp.remaining_bytes()).decode('utf-8', 'ignore').encode()

    try:
        with tempfile.NamedTemporaryFile(suffix=fuzz_ext) as tempf:
            tempf.write(fuzz_data)
            tempf.seek(0)
            tempf.flush()
            fuzz_func(tempf.name)
    except (EmptyDataError, laspy.LaspyException, IndexError, ParserError):
        return -1
    except ValueError as e:
        if 'OFF' in str(e) or 'pickle' in str(e) or 'ply' in str(e):
            return -1
        raise




def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
