# warcforhumans
warcforhumans is a Python package that lets you write WARC records with a simple `requests` session.

> [!CAUTION]
> This project is still a work-in-progress, and has not been extensively tested.

# Usage

Simple example:

```python
from warcforhumans.api import WARCWriter

warc_writer = WARCWriter("example", rotate_mb=0)

s = warc_writer.get_session()
r = s.get("http://digitaldragon.dev")
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

or a ZSTD dictionary:

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


