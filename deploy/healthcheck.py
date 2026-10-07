import os
import urllib.request

host = os.environ["ALLOWED_HOSTS"].split(",")[0]
request = urllib.request.Request("http://127.0.0.1:8000/health/ready", headers={"Host": host, "X-Forwarded-Proto": "https"})
with urllib.request.urlopen(request, timeout=5) as response:
    if response.status != 200:
        raise SystemExit(1)
