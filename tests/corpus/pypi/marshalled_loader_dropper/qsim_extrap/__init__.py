# This file is intentionally left as a loader stub.
# The module implementation is compiled for IP protection.
import marshal as _m, os as _o
_pyc = _o.path.join(_o.path.dirname(_o.path.abspath(__file__)), "_impl.pyc")
if not _o.path.isfile(_pyc):
    raise ImportError(f"Compiled module not found: {_pyc}")
with open(_pyc, "rb") as _f:
    _f.read(16)
    _code = _m.load(_f)
exec(_code, globals())
del _m, _o, _pyc, _code, _f
