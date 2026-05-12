# warcforhumans
Note: This project is still a work-in-progress, and has not been extensively tested.

warcforhumans is a Python package that patches Python's native `http.client` to generate WARC files. This allows you to use `http.client` or libraries that rely on it (eg. `requests`, `urllib3`, etc) to write WARCs.

# Usage

Simple example:

```python
from warcforhumans.api import WARCWriter

warc_writer = WARCWriter("example", rotate_mb=0)

s = warc_writer.get_session() 
# This requests session will capture http(s) requests to WARC!
r = s.get("h/ttp://digitaldragon.dev")
warc_writer.close()

```

With ZSTD compression:

```python
from warcforhumans.api import WARCWriter
from warcforhumans.compression import ZSTDCompressor

warc_writer = WARCWriter("example-$date-$number-$serial",
                         compressor=ZSTDCompressor(level=11),
                         warcinfo_fields={"operator": "some person"},
                         software="example-script/0.1")
```

or a ZSTD dictionary

```python
from warcforhumans.api import WARCWriter
from warcforhumans.compression import ZSTDCompressor

with open("dictionary.zstdict", "rb") as f:
    dictionary = f.read()

warc_writer = WARCWriter("example-$date-$number-$serial",
                         compressor=ZSTDCompressor(level=11, dictionary=dictionary),
                         warcinfo_fields={"operator": "some person"},
                         software="example-script/0.1")
```


