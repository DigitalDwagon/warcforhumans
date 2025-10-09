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
    def __init__(self, level: int = 11):
        self.level = level

    def write_record(self, record, file):
        cctx = zstd.ZstdCompressor(level=self.level)
        compressor = cctx.stream_writer(file)
        for chunk in record.serialize_stream():
            compressor.write(chunk)
        compressor.flush(zstd.FLUSH_FRAME)

    def file_extension(self) -> str:
        return ".zst"

    def start(self, file):
        pass


class ZSTDCompressorWithDictionary(Compressor):
    def __init__(self, dict, level: int = 11, compress_dict: bool = False):
        self.level = level
        self.dict = open(dict, "rb").read()
        self.compress_dict = compress_dict

        # detect if dictionary is zstd-compressed

    def write_record(self, record, file):
        cctx = zstd.ZstdCompressor(level=self.level, dict_data=zstd.ZstdCompressionDict(self.dict))
        compressor = cctx.stream_writer(file)
        for chunk in record.serialize_stream():
            compressor.write(chunk)
        compressor.flush(zstd.FLUSH_FRAME)

    def file_extension(self) -> str:
        return ".zst"

    def start(self, file):
        # Write a skippable frame with the dictionary at the start of the file
        # https://www.rfc-editor.org/rfc/rfc8878.txt
        if self.compress_dict:
            cctx = zstd.ZstdCompressor(level=self.level)
            self.dict = cctx.compress(self.dict)

        # magic number 0x184D2A5D per https://iipc.github.io/warc-specifications/specifications/warc-zstd/
        file.write(b'\x5D\x2A\x4D\x18')
        size = len(self.dict)
        file.write(size.to_bytes(4, 'little'))
        file.write(self.dict)