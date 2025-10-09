from io import BytesIO
from datetime import datetime

class WARCRecord:
    def __init__(self):
        # https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1-annotated/#warc-type-mandatory

        self.headers: dict[str, list[str]] = {}
        self.content: BytesIO = None

    def set_header(self, key: str, value):
        if isinstance(value, list):
            self.headers[key] = value
        else:
            self.headers[key] = [value]

    def add_header(self, key: str, value: str):
        if key in self.headers:
            self.headers[key].append(value)
        else:
            self.headers[key] = [value]

    def set_headers(self, headers: dict[str, str]):
        for key, value in headers.items():
            self.set_header(key, value)

    def set_type(self, type: str):
        valid_warc_record_types = {"warcinfo", "response", "resource", "request", "metadata", "revisit", "conversion",
                                   "continuation"}
        if type not in valid_warc_record_types:
            raise ValueError(f"Invalid WARC record type: {type}")

        self.set_header("WARC-Type", type)

    def set_content(self, content: bytes):
        self.content = content
        self.set_header("Content-Length", str(len(content)))

    def set_content_stream(self, stream: BytesIO):
        self.content = stream
        self.set_header("Content-Length", str(len(stream.getbuffer())))

    def date_now(self):
        self.set_header("WARC-Date", datetime.now().isoformat())


    def serialize_stream(self):
        if self.content is None:
            raise ValueError("Content is not set")

        mandatory_headers = ["WARC-Record-ID", "Content-Length", "WARC-Date", "WARC-Type"]
        for header in mandatory_headers:
            if header not in self.headers:
                raise ValueError(f"Mandatory header {header} is missing")

        yield b"WARC/1.1\r\n"
        for key, value in self.headers.items():
            for v in value:
                yield f"{key}: {v}\r\n".encode("utf-8")
        yield b"\r\n"

        # Stream the content in chunks
        if isinstance(self.content, bytes):
            yield self.content
        else:
            content_buffer = self.content.getbuffer()
            chunk_size = 8192  # Define a chunk size
            for i in range(0, len(content_buffer), chunk_size):
                yield content_buffer[i:i + chunk_size]

        yield b"\r\n\r\n"