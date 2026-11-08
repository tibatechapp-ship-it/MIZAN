import requests

r = requests.post(url, json=payload, timeout=5, verify=False)
