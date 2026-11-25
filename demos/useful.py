# Fetches data from the local mock API (start demos/mock_server.py first).
# Firecracker backend: change the host to 172.16.0.1 (the TAP address).
import json
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8080/data", timeout=3) as r:
    data = json.load(r)
print(data["items"][:5])
