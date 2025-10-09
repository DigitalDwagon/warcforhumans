import requests
import warcforhumans.http

# --- Example usage with urllib3 ---
if __name__ == "__main__":
    """import urllib3
    urllib3.disable_warnings()
    http = urllib3.PoolManager()
    resp = http.request("GET", "https://wiki.archiveteam.org")
    print("Response status:", resp.status)
    print("Body length:", len(resp.data))"""
    r = requests.get("http://digitaldragon.dev")
    #print(r.text)
