import shutil

import zstandard as zstd

class Compressor:
    def write_record(self, record, file):
        for chunk in record.serialize_stream():
            file.write(chunk)

    def file_extension(self) -> str:
        return ""

    def start(self, file):
        pass

class ZSTDCompressor(Compressor):
    def __init__(self, dictionary = None, level: int = 11):
        self.level = level
        if dictionary:
            self.dict = dictionary

        # detect if dictionary is zstd-compressed

    def write_record(self, record, file):
        if self.dict is not None:
            cctx = zstd.ZstdCompressor(level=self.level, dict_data=zstd.ZstdCompressionDict(self.dict))
        else:
            cctx = zstd.ZstdCompressor(level=self.level)

        compressor = cctx.stream_writer(file)
        for chunk in record.serialize_stream():
            compressor.write(chunk)
        compressor.flush(zstd.FLUSH_FRAME)

    def file_extension(self) -> str:
        return ".zst"

    def start(self, file):
        if self.dict is None:
            return

        # Write a skippable frame with the dictionary at the start of the file
        # magic number 0x184D2A5D per https://iipc.github.io/warc-specifications/specifications/warc-zstd/

        file.write(b'\x5D\x2A\x4D\x18')
        size = len(self.dict)
        file.write(size.to_bytes(4, 'little'))
        file.write(self.dict)
