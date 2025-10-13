import requests
import warcforhumans.capture.http as capture
from warcforhumans.warc.api import WARCFile
from warcforhumans.warc.compression import ZSTDCompressor

# --- Example usage with urllib3 ---
if __name__ == "__main__":
    warc_file = WARCFile("test")
    capture.warc_file = warc_file
    r = requests.post("https://httpbin.org/post", "example", headers={"Accept-Encoding": "identity"})
    warc_file.close()
