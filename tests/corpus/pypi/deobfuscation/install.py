import marshal
import zlib

_data = b"<packed-bytecode-here>"

exec(marshal.loads(zlib.decompress(_data)))
