import os
import queue

import pytest
import requests
import socket
import threading

from warcforhumans.api import WARCWriter
import warcforhumans.capture.http as capture

@pytest.fixture
def fake_http_server():
    def start_server(response_content, host='127.0.0.1'):
        port_queue = queue.Queue()

        def server():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((host, 0))
                server_socket.listen(1)
                _, assigned_port = server_socket.getsockname()
                port_queue.put(assigned_port)
                conn, _ = server_socket.accept()
                with conn:
                    conn.recv(1024)  # Read the request (optional)
                    conn.sendall(response_content)

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        return f"http://{host}:{port_queue.get()}"

    return start_server


@pytest.fixture
def warc_writer(tmp_path):
    warc_path = str(tmp_path / "test")
    writer = WARCWriter(warc_path)
    capture.warc_writer = writer
    return writer

@pytest.fixture
def verify_content_match(tmp_path, warc_writer, fake_http_server):
    def verify(response_content):
        r = requests.get(fake_http_server(response_content))
        warc_writer.close()
        fp = tmp_path / "test.warc"

        assert os.path.exists(fp), "WARC file does not exist"

        with open(fp, "rb") as f:
            file_content = f.read()
            index = file_content.find(response_content)

            assert index != -1, "Response content not found in WARC file!"

            start_index = file_content.rfind(b"WARC/1.1", 0, index)
            assert start_index != -1, "WARC record start not found!"

            # parse the Content-Length warc header
            end_index = file_content.find(b"\r\n\r\n", start_index) + 4
            header_block = file_content[start_index:end_index]
            headers = header_block.split(b"\r\n")
            content_length = None
            for header in headers:
                if header.lower().startswith(b"content-length:"):
                    content_length = int(header.split(b":")[1].strip())
                    break
            assert content_length is not None, "Content-Length header not found for WARC record!"

            warc_content = file_content[end_index:end_index + content_length]

            assert warc_content == response_content, "Response content not properly stored in WARC record!"

    return verify