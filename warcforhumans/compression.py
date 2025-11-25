from typing import BinaryIO

import zstandard as zstd

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from warcforhumans.api import WARCRecord


class Compressor:
    """
    A no-op WARC record compressor for other code to use as a base.
    """
    def write_record(self, record: 'WARCRecord', file: BinaryIO):
        """
        Write an entire record.
        :param record: The WARCRecord to write
        :param file: The file on disk to write to
        :return:
        """
        for chunk in record.serialize_stream():
            file.write(chunk)

    def file_extension(self) -> str:
        """
        The file extension to add after .warc
        :return: A file extension (ex. ".zst") for this compression type
        """
        return ""

    def start(self, file: BinaryIO):
        """
        Called when a new WARC file is started, in case some data (ex. a compression dictionary) needs to be written to
            the start of every file.
        :param file: The empty file to write to.
        :return:
        """
        pass


class ZSTDCompressor(Compressor):
    def __init__(self, dictionary: bytes = None, level: int = 11):
        """
        A compressor for zstd WARCs.
        :param dictionary: The compression dictionary to use, if any.
        :param level: zstd compression level.
        """
        self.level = level
        self.dict = dictionary

        # detect if dictionary is zstd-compressed

    def write_record(self, record: 'WARCRecord', file: BinaryIO):
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

    def start(self, file: BinaryIO):
        if self.dict is None:
            return

        # Write a skippable frame with the dictionary at the start of the file
        # magic number 0x184D2A5D per https://iipc.github.io/warc-specifications/specifications/warc-zstd/

        file.write(b'\x5D\x2A\x4D\x18')
        size = len(self.dict)
        file.write(size.to_bytes(4, 'little'))
        file.write(self.dict)


class GZIPCompressor(Compressor):
    def __init__(self, level: int = 6):
        """
        A compressor for gzip WARCs
        :param level: gzip compression level.
        """
        self.level = level

    def write_record(self, record: 'WARCRecord', file: BinaryIO):
        import gzip
        with gzip.GzipFile(fileobj=file, mode='ab', compresslevel=self.level) as gz_file:
            for chunk in record.serialize_stream():
                gz_file.write(chunk)

    def file_extension(self) -> str:
        return ".gz"
