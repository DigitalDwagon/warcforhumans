import sys

import requests
import capture.http
from warcforhumans.warc.api import WARCFile

# --- Example usage with urllib3 ---
if __name__ == "__main__":
    """import urllib3
    urllib3.disable_warnings()
    http = urllib3.PoolManager()
    resp = http.request("GET", "https://wiki.archiveteam.org")
    print("Response status:", resp.status)
    print("Body length:", len(resp.data))"""
    #r = requests.get("http://digitaldragon.dev", headers={"Accept-Encoding": "identity"})
    #print(r.text)
    print(sys.version)
    warc_file = WARCFile("test.warc")
    capture.http.warc_file = warc_file
    r = requests.get("http://digitaldragon.dev", headers={"Accept-Encoding": "identity"})
    warc_file.close()