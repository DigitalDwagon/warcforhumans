# warcforhumans
warcforhumans is a Python package that lets you write WARC records.

> [!CAUTION]
> This project is still a work-in-progress, and has not been extensively tested.

# Usage

First, open a WARCWriter:

```python
from warcforhumans.api import WARCWriter

warc_writer = WARCWriter("example", rotate_mb=0)
```

You can also specify other options, like ZSTD compression:

```python
from warcforhumans.api import WARCWriter
from warcforhumans.compression import ZSTDCompressor

warc_writer = WARCWriter("example-$date-$number-$serial",
                         compressor=ZSTDCompressor(level=11),
                         warcinfo_fields={"operator": "some person"},
                         software="example-script/0.1")
```

a ZSTD dictionary:

```python
with open("dictionary.zstdict", "rb") as f:
    dictionary = f.read()

warc_writer = WARCWriter("example-$date-$number-$serial",
                         compressor=ZSTDCompressor(level=11, dictionary=dictionary)
                         )
```

or GZIP:

```python
warc_writer = WARCWriter("example-$date-$number-$serial",
                         compressor=GZIPCompressor()
                         )
```

## Capture with requests:
You can get a requests session from the `WARCWriter` that will write requests and responses to WARC:
```python
s = warc_writer.get_session()
r = s.get("http://digitaldragon.dev")
warc_writer.close()
```

## Capture with h11:
You can also use a `WARCWritingH11Connection` to send and receive `h11` events directly:

```python
import h11
from warcforhumans.capture.connection import ConnectionInfo, WARCWritingH11Connection
conn = WARCWritingH11Connection(
    ConnectionInfo(scheme="https", host="www.digitaldragon.dev", port=443),
    warc_writer
)

req = h11.Request(
    method = "GET",
    headers = [("Host", "www.digitaldragon.dev")],
    target = "/"
)
conn.send_event(req)
conn.send_event(h11.EndOfMessage())

resp = conn.next_event(4096)

conn.close()
warc_writer.close()
```


