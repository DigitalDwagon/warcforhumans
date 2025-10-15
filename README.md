# warcforhumans
Note: This project is still a work-in-progress, and has not been extensively tested.

warcforhumans is a Python package that patches Python's native `http.client` to generate WARC files. This allows you to use `http.client` or libraries that rely on it (eg. `requests`, `urllib3`, etc) to write WARCs.

# Usage

Simple example:

```python
import requests
import warcforhumans.capture.http as capture
from warcforhumans.api import WARCWriter

warc_writer = WARCWriter("example", rotate_mb=0)
capture.warc_writer = warc_writer
r = requests.get("http://digitaldragon.dev")
warc_writer.close()

```

With ZSTD compression:

```python
import requests
import warcforhumans.capture.http as capture
from warcforhumans.api import WARCWriter
from warcforhumans.compression import ZSTDCompressor

warc_writer = WARCWriter("example-$date-$number-$serial",
                         compressor=ZSTDCompressor(level=11),
                         warcinfo_headers={"operator": "some person"},
                         software="example-script/0.1")
capture.warc_writer = warc_writer
r = requests.get("http://digitaldragon.dev")
warc_writer.close()
```

or a ZSTD dictionary

```python
import requests
import warcforhumans.capture.http as capture
from warcforhumans.api import WARCWriter
from warcforhumans.compression import ZSTDCompressor

with open("dictionary.zstdict", "rb") as f:
    dictionary = f.read()

warc_writer = WARCWriter("example-$date-$number-$serial",
                         compressor=ZSTDCompressor(level=11, dictionary=dictionary),
                         warcinfo_headers={"operator": "some person"},
                         software="example-script/0.1")
capture.warc_writer = warc_writer
r = requests.get("http://digitaldragon.dev")
warc_writer.close()
```


