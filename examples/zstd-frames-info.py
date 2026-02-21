from io import BufferedRandom

import zstandard as zstd # or from compression import zstd in Python 3.14+
import io

from zstandard.backend_c import BufferWithSegments


def process_zstd_frames(data: BufferedRandom):
    """
    Processes a byte stream that may contain multiple Zstandard frames,
    printing information about each frame and its decompressed content.
    """
    dctx = zstd.ZstdDecompressor()
    frame_count = 0
    data_size = data.seek(0, io.SEEK_END)
    data.seek(0)

    with dctx.stream_reader(data) as reader:
        frame_count += 1
        print(f"Frame 1: {reader.readall()!r}\n")

    with dctx.stream_reader(data) as reader2:
        frame_count += 1
        print(f"Frame 2: {reader2.readall()!r}\n")




# Example usage with a multi-frame Zstandard stream
# In a real scenario, 'compressed_data' would come from a file or network stream.
compressor = zstd.ZstdCompressor(level=1)
frame1 = compressor.compress(b"This is the first Zstandard frame.")
frame2 = compressor.compress(b"And this is the second frame, following the first.")
frame3 = compressor.compress(b"Finally, a third frame to demonstrate the processing.")

compressed_data = BufferedRandom(io.BytesIO(frame1 + frame2 + frame3))

process_zstd_frames(compressed_data)