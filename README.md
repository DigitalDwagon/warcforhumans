# warcforhumans

warcforhumans is a Python package that patches Python's native `http.client` to generate WARC files. This allows you to use `http.client` or libraries that rely on it (eg. `requests`, `urllib3`, etc) to write WARCs.

`zstd` compression is supported, with or without dictionaries. `gzip` compression is not yet supported.

# Usage

Quick start:
```python
import requests
import warcforhumans.capture.http as capture
from warcforhumans.warc.api import WARCFile

warc_file = WARCFile("example")
capture.warc_file = warc_file

r = requests.get("http://digitaldragon.dev")
warc_file.close()
```

With ZSTD compression:
```python
import requests
import warcforhumans.capture.http as capture
from warcforhumans.warc.api import WARCFile
from warcforhumans.warc.compression import ZSTDCompressor

warc_file = WARCFile("example", compressor=ZSTDCompressor(level=11))
# or with a dictionary:
dictionary = open("dictionary.zstdict", "rb").read()
warc_file = WARCFile("example", compressor=ZSTDCompressor(dictionary=dictionary, level=11))

capture.warc_file = warc_file
r = requests.get("http://digitaldragon.dev")
warc_file.close()
```

Need to skip saving a response to WARC?
```python
warc_file.discard_last()

# Warning: This is not necessarily thread safe. Use .get_last() and then .discard(ID) as a safer alternative 
```


