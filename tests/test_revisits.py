from pathlib import Path

from warcforhumans.api import WARCRecord, WARCWriter


def _read_warc_records(path: Path) -> list[tuple[dict[str, list[str]], bytes]]:
    data = path.read_bytes()
    records: list[tuple[dict[str, list[str]], bytes]] = []
    offset = 0

    while True:
        start = data.find(b"WARC/1.1\r\n", offset)
        if start == -1:
            break

        header_end = data.find(b"\r\n\r\n", start)
        assert header_end != -1, "Could not find the end of the WARC header block"

        header_lines = data[start:header_end].split(b"\r\n")
        headers: dict[str, list[str]] = {}
        for line in header_lines[1:]:
            key, value = line.split(b": ", 1)
            headers.setdefault(key.decode("utf-8"), []).append(value.decode("utf-8"))

        content_length = int(headers[WARCRecord.CONTENT_LENGTH][0])
        body_start = header_end + 4
        body_end = body_start + content_length
        records.append((headers, data[body_start:body_end]))
        offset = body_end + 4

    return records


def _capture_duplicate_responses(tmp_path: Path, fake_http_server, response_bytes: bytes, *, revisit: bool = True):
    writer = WARCWriter(str(tmp_path / "test"), revisit=revisit)
    session = writer.get_session()

    first_url = fake_http_server(response_bytes)
    second_url = fake_http_server(response_bytes)

    session.get(first_url)
    session.get(second_url)
    writer.close()

    return _read_warc_records(tmp_path / "test.warc")


def test_revisit_response_body_is_the_http_header_block(tmp_path, fake_http_server):
    body = b"This payload is intentionally repeated to trigger a revisit record." * 64
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"X-Test: revisit\r\n"
        b"\r\n" +
        body
    )

    records = _capture_duplicate_responses(tmp_path, fake_http_server, response)

    record_types = [headers[WARCRecord.WARC_TYPE][0] for headers, _ in records]
    assert record_types.count("revisit") == 1
    assert record_types.count("response") == 1

    response_headers, response_body = next((headers, body_bytes) for headers, body_bytes in records if headers[WARCRecord.WARC_TYPE][0] == "response")
    revisit_headers, revisit_body = next((headers, body_bytes) for headers, body_bytes in records if headers[WARCRecord.WARC_TYPE][0] == "revisit")

    expected_header_block = response.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"

    assert response_body == response
    assert revisit_body == expected_header_block
    assert revisit_body != response_body
    assert revisit_body.startswith(b"HTTP/1.1 200 OK\r\n")
    assert body not in revisit_body

    assert revisit_headers[WARCRecord.WARC_REFERS_TO][0] == response_headers[WARCRecord.WARC_RECORD_ID][0]
    assert revisit_headers[WARCRecord.WARC_REFERS_TO_TARGET_URI][0] == response_headers[WARCRecord.WARC_TARGET_URI][0]
    assert revisit_headers[WARCRecord.WARC_REFERS_TO_DATE][0] == response_headers[WARCRecord.WARC_DATE][0]


def test_duplicate_response_stays_a_normal_response_when_revisit_tracking_is_disabled(tmp_path, fake_http_server):
    body = b"revisit tracking disabled" * 32
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" +
        body
    )

    records = _capture_duplicate_responses(tmp_path, fake_http_server, response, revisit=False)

    record_types = [headers[WARCRecord.WARC_TYPE][0] for headers, _ in records]
    assert record_types.count("revisit") == 0
    assert record_types.count("response") == 2

    response_bodies = [body_bytes for headers, body_bytes in records if headers[WARCRecord.WARC_TYPE][0] == "response"]
    assert response_bodies == [response, response]


