import requests
import warcforhumans.capture.http as capture
from warcforhumans.warc.api import WARCFile, WARCWriter
from warcforhumans.warc.compression import ZSTDCompressor

# --- Example usage with urllib3 ---
if __name__ == "__main__":
    warc_writer = WARCWriter("test-$date-$number")
    capture.warc_writer = warc_writer
    r = requests.post("http://digitaldragon.dev", "example", headers={"Accept-Encoding": "identity"})
    warc_writer.close()
