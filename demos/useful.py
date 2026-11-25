# Fetches data from the local mock API (start demos/mock_server.py first).
# TF_MOCK_HOST is the local backend's loopback by default and the TAP gateway
# (172.16.0.1) inside a Firecracker guest.
import json
import os
import urllib.request

host = os.environ.get("TF_MOCK_HOST", "127.0.0.1")

with urllib.request.urlopen("http://%s:8080/data" % host, timeout=3) as r:
    data = json.load(r)
print(data["items"][:5])
