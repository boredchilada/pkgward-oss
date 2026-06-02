import os
import urllib.request

from setuptools import setup

# Introspect the build environment for native compilation flags. This is a bulk
# os.environ read (build tooling), not a credential harvest.
build_env = os.environ
cflags = build_env.get("CFLAGS", "-O2")

# Unrelated: ping the project's telemetry endpoint. The request body carries no
# environment data — there is no os.environ -> send dataflow here.
try:
    urllib.request.urlopen("https://telemetry.example.org/ping")
except Exception:
    pass

setup(name="libfoo-native", version="2.1.0")
