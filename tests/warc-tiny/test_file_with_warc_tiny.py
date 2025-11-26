import sys
from pathlib import Path

import pytest
import requests
import importlib.util


def test_file_with_warc_tiny(tmp_path, warc_writer):
    urls = ["http://digitaldragon.dev", "http://digitaldragon.dev", "https://wiki.archiveteam.org", "https://archive.org"]
    for url in urls:
        r = requests.get(url)
    warc_writer.close()
    path = (tmp_path / "test.warc")

    warc_tiny_path = Path(__file__).parent / "warc-tiny.py"
    spec = importlib.util.spec_from_file_location("warc_tiny", warc_tiny_path)
    warc_tiny = importlib.util.module_from_spec(spec)
    sys.modules["warc_tiny"] = warc_tiny
    spec.loader.exec_module(warc_tiny)

    processor = warc_tiny.VerifyMode()
    processor.process_event(warc_tiny.NewFile(str(path)))
    for event in warc_tiny.iter_warc(str(path)):
        processor.process_event(event)
    processor.process_event(warc_tiny.EndOfFile(str(path)))