import requests
import warcforhumans.capture.http as capture
from warcforhumans.warc.api import WARCFile
from warcforhumans.warc.compression import ZSTDCompressor

# --- Example usage with urllib3 ---
if __name__ == "__main__":
    warc_file = WARCFile("test", compressor=ZSTDCompressor(dictionary=(open("test_zstd_dict", "rb").read()), level=11))
    capture.warc_file = warc_file
    r = requests.get("http://digitaldragon.dev", headers={"Accept-Encoding": "identity"})
    warc_file.close()
