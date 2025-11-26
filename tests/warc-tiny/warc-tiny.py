# https://gitea.arpa.li/JustAnotherArchivist/little-things/src/branch/master/warc-tiny
# This file was not written as part of this project. Different license terms may apply.

#!/usr/bin/env python3

# Tiny tool for WARC stuff.
# Operating modes:
#  warc-tiny colour FILES  --  coloured output of the WARCs for easier reading
#  warc-tiny dump-responses [-m|--meta] FILES  --  dump the HTTP response bodies to stdout
#    With --meta, prefix every line with the filename, record offset, record ID, and target URI; e.g. 'file.warc.gz:123:<urn:uuid:41b76f1f-f946-4723-91f8-cee6491e92f3>:<https://example.org/>:    foobar'
#      The record offset may be -1 if it is not known.
#      The filename is wrapped in angled brackets if it contains a colon; the target URI is always wrapped in angled brackets (since it virtually always contains a colon).
#  warc-tiny scrape [-u|--urls] FILES  --  extract all links and page requisites from the records; produces lines of filename, record offset, record URI, link type, inline flag, and URL as JSONL
#    With --urls, only the URL is printed.
#    wpull's scrapers are used for the extraction.
#  warc-tiny verify FILES  --  verify the integrity of a WARC by comparing the digests

import base64
import contextlib
import enum
import gzip
import hashlib
import json
import sys
import tempfile
import zlib

try:
	import wpull.body
	import wpull.document.htmlparse.lxml_
	try:
		import wpull.protocol.http.request as wpull_protocol_http_request # wpull 2.x
	except ImportError:
		import wpull.http.request as wpull_protocol_http_request # wpull 1.x
	import wpull.scraper.base
	import wpull.scraper.css
	import wpull.scraper.html
	import wpull.scraper.javascript
	import wpull.scraper.sitemap
except ImportError:
	wpull = None


def GzipDecompressor():
	return zlib.decompressobj(16 + zlib.MAX_WBITS)


class DummyDecompressor:
	def decompress(self, data):
		return data


class Event:
	pass


class FileEvent(Event):
	def __init__(self, filename):
		self._filename = filename

	@property
	def filename(self):
		return self._filename


class NewFile(FileEvent):
	pass


class BeginOfRecord(Event):
	def __init__(self, warcHeaders, rawData):
		self._warcHeaders = warcHeaders
		self._rawData = rawData

	@property
	def warcHeaders(self):
		return self._warcHeaders

	@property
	def rawData(self):
		return self._rawData


class HTTPHeaders(Event):
	def __init__(self, headers):
		self._headers = headers

	@property
	def headers(self):
		return self._headers


class _DataChunk(Event):
	def __init__(self, data):
		self._data = data

	@property
	def data(self):
		return self._data

	def __repr__(self):
		return '{}({!r}{})'.format(type(self).__name__, self._data[:50], '...' if len(self._data) > 50 else '')


class WARCBlockChunk(_DataChunk):
	def __init__(self, data, isHttpHeader = None):
		super().__init__(data)
		self._isHttpHeader = isHttpHeader

	@property
	def isHttpHeader(self):
		# True: the chunk represents (part of) the HTTP header; False: the chunk represents (part of) the HTTP body; None: the chunk is not part of an HTTP record
		return self._isHttpHeader


class RawHTTPBodyChunk(_DataChunk):
	'''
	Because many tools misunderstood the WARC specifications, the Payload-Digest was often implemented without stripping transfer encoding.
	This is like HTTPBodyChunk but without transfer encoding stripping.
	'''


class HTTPBodyChunk(_DataChunk):
	'''
	Representing a part of the HTTP body with transfer encoding stripped.
	'''


class EndOfRecord(Event):
	pass


class WARCParsingIssue(enum.Enum):
	TRUNCATED_FILE = enum.auto()
	MALFORMED_HTTP_RECORD = enum.auto()
	EMPTY_FILE = enum.auto()


class WARCParsingIssueEvent(Event):
	def __init__(self, issue, message = None):
		self.issue = issue
		self.message = message


class EndOfFile(FileEvent):
	pass


@contextlib.contextmanager
def open_warc(f):
	if hasattr(f, 'read'):
		yield f
	else:
		with open(f, 'rb') as fp:
			yield fp


def iter_warc(f):
	# Yields Events
	# BeginOfRecord's rawData does not include the CRLF CRLF at the end of the headers, and WARCBlockChunk does not contain the CRLF CRLF after the block either.

	with open_warc(f) as fp:
		buf = b''
		isEmpty = True
		while True:
			# Read WARC header
			while b'\r\n\r\n' not in buf:
				try:
					d = fp.read(16777216)
				except EOFError:
					break
				if not d:
					break
				buf += d
			if not buf:
				if isEmpty:
					print('Error: empty file', file = sys.stderr)
					yield WARCParsingIssueEvent(WARCParsingIssue.EMPTY_FILE)
				break
			isEmpty = False
			assert b'\r\n\r\n' in buf
			warcHeaderBuf, buf = buf.split(b'\r\n\r\n', 1)
			assert warcHeaderBuf.startswith(b'WARC/1.0\r\n') or warcHeaderBuf.startswith(b'WARC/1.1\r\n')
			assert b'\r\nContent-Length:' in warcHeaderBuf
			warcHeaders = tuple(tuple(map(bytes.strip, x.split(b':', 1))) for x in warcHeaderBuf.split(b'\r\n'))
			warcContentType = next(x[1] for x in warcHeaders if x[0] == b'Content-Type')
			warcContentLength = int(next(x[1] for x in warcHeaders if x[0] == b'Content-Length'))
			warcType = next(x[1] for x in warcHeaders if x[0] == b'WARC-Type')
			yield BeginOfRecord(warcHeaders, warcHeaderBuf)
			recordID = next(x[1] for x in warcHeaders if x[0] == b'WARC-Record-ID')

			# Read WARC block (and skip CRLFCRLF at the end of the record)
			if len(buf) < warcContentLength + 4:
				try:
					buf = buf + fp.read(warcContentLength + 4 - len(buf))
				except EOFError:
					pass
			if len(buf) < warcContentLength + 4:
				print('Error: truncated WARC', file = sys.stderr)
				yield WARCParsingIssueEvent(WARCParsingIssue.TRUNCATED_FILE)
				break
			warcContent = buf[:warcContentLength]
			buf = buf[warcContentLength + 4:]

			# Decode HTTP body if appropriate
			if warcContentType in (b'application/http;msgtype=request', b'application/http; msgtype=request') and warcType == b'request':
				httpType = 'request'
			elif warcContentType in (b'application/http;msgtype=response', b'application/http; msgtype=response') and warcType == b'response':
				httpType = 'response'
			else:
				httpType = None
			if httpType is not None:
				if b'\r\n\r\n' in warcContent:
					httpHeaders, httpBody = warcContent.split(b'\r\n\r\n', 1)

					# Parse headers and extract transfer encoding
					httpHeaderLines = [tuple(map(bytes.strip, x.split(b':', 1))) for x in httpHeaders.split(b'\r\n')]
					chunked = False
					gzipped = False
					if b'\r\ntransfer-encoding' in httpHeaders.lower():
						transferEncoding = next(x[1] for x in httpHeaderLines if x[0].lower() == b'transfer-encoding')
						transferEncodings = set(map(bytes.strip, transferEncoding.split(b',')))
						chunked = b'chunked' in transferEncodings
						gzipped = b'gzip' in transferEncodings

					yield WARCBlockChunk(httpHeaders + b'\r\n\r\n', isHttpHeader = True)
					yield HTTPHeaders(httpHeaderLines)
					yield WARCBlockChunk(httpBody, isHttpHeader = False)
					yield RawHTTPBodyChunk(httpBody)

					# Decode body
					if gzipped:
						httpDecompressor = GzipDecompressor()
					else:
						httpDecompressor = DummyDecompressor()
					if chunked:
						pos = 0
						while True:
							try:
								chunkLineEnd = httpBody.index(b'\r\n', pos)
							except ValueError:
								message = 'could not find chunk line end in record {}'.format(recordID)
								print('Error: {}, skipping'.format(message), file = sys.stderr)
								yield WARCParsingIssueEvent(WARCParsingIssue.MALFORMED_HTTP_RECORD, message)
								break
							chunkLine = httpBody[pos:chunkLineEnd]
							if b';' in chunkLine:
								chunkLength = chunkLine[:chunkLine.index(b';')].strip()
							else:
								chunkLength = chunkLine.strip()
							if chunkLength.lstrip(b'0123456789abcdefABCDEF') != b'':
								message = 'malformed chunk length {!r} in record {}'.format(chunkLength, recordID)
								print('Error: {}, skipping'.format(message), file = sys.stderr)
								yield WARCParsingIssueEvent(WARCParsingIssue.MALFORMED_HTTP_RECORD, message)
								break
							chunkLength = int(chunkLength, base = 16)
							if chunkLength == 0:
								break
							chunk = httpDecompressor.decompress(httpBody[chunkLineEnd + 2 : chunkLineEnd + 2 + chunkLength])
							yield HTTPBodyChunk(chunk)
							pos = chunkLineEnd + 2 + chunkLength + 2
					else:
						yield HTTPBodyChunk(httpDecompressor.decompress(httpBody))
				else:
					message = 'malformed HTTP request or response in record {}'.format(recordID)
					print('Warning: {}, skipping'.format(message), file = sys.stderr)
					yield WARCParsingIssueEvent(WARCParsingIssue.MALFORMED_HTTP_RECORD, message)
					yield WARCBlockChunk(warcContent)
			else:
				yield WARCBlockChunk(warcContent)
			yield EndOfRecord()


class ProcessMode:
	@classmethod
	def split_args(cls, args):
		'''Split args into arguments to be passed into __init__ and filenames'''
		return (), args

	def process_event(self, event):
		raise NotImplementedError


class Digest:
	def __init__(self, digest):
		self._digest = digest

	def format(self, digest = None):
		raise NotImplementedError

	def equals(self, digest):
		return self._digest == digest


class Base32Digest(Digest):
	def format(self, digest = None):
		return base64.b32encode(digest if digest else self._digest)


class HexDigest(Digest):
	def format(self, digest = None):
		return (digest if digest else self._digest).hex()


class VerificationError(Exception):
	pass


class VerifyMode(ProcessMode):
	def __init__(self):
		self._blockDigester = None
		self._recordedBlockDigest = None
		self._payloadDigester = None
		self._brokenPayloadDigester = None
		self._recordedPayloadDigest = None
		self._printedBrokenPayloadWarning = False
		self._verificationFailed = False

	def parse_digest(self, digest):
		if not digest.startswith(b'sha1:'):
			print('Warning: don\'t understand hash format: {!r}'.format(digest), file = sys.stderr)
			return None
		if len(digest) == 37 and digest.rstrip(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') == b'sha1:': # 5 for 'sha1:' + 32 for base-32 hash
			return Base32Digest(base64.b32decode(digest[5:]))
		if len(digest) == 45 and digest.rstrip(b'0123456789abcdef') == b'sha1:':
			return HexDigest(bytes.fromhex(digest[5:].decode('ascii')))
		return None

	def process_event(self, event):
		if type(event) is NewFile:
			self._printedBrokenPayloadWarning = False
			self._verificationFailed = False
		elif type(event) is BeginOfRecord:
			if any(x[0] == b'WARC-Block-Digest' for x in event.warcHeaders):
				self._blockDigester = hashlib.sha1()
				self._recordedBlockDigest = self.parse_digest(next(x[1] for x in event.warcHeaders if x[0] == b'WARC-Block-Digest'))
			else:
				self._blockDigester = None
				self._recordedBlockDigest = None
			if any(x[0] == b'WARC-Payload-Digest' for x in event.warcHeaders):
				self._payloadDigester = hashlib.sha1()
				self._brokenPayloadDigester = hashlib.sha1()
				self._recordedPayloadDigest = self.parse_digest(next(x[1] for x in event.warcHeaders if x[0] == b'WARC-Payload-Digest'))
			else:
				self._payloadDigester = None
				self._brokenPayloadDigester = None
				self._recordedPayloadDigest = None
			self._recordID = next(x[1] for x in event.warcHeaders if x[0] == b'WARC-Record-ID')
			self._recordType = next(x[1] for x in event.warcHeaders if x[0] == b'WARC-Type')
		elif type(event) is WARCBlockChunk:
			if self._blockDigester:
				self._blockDigester.update(event.data)
		elif type(event) is HTTPBodyChunk:
			if self._payloadDigester:
				self._payloadDigester.update(event.data)
		elif type(event) is RawHTTPBodyChunk:
			if self._brokenPayloadDigester:
				self._brokenPayloadDigester.update(event.data)
		elif type(event) is WARCParsingIssueEvent:
			self._verificationFailed = True
		elif type(event) is EndOfRecord:
			if self._blockDigester and self._recordedBlockDigest:
				if not self._recordedBlockDigest.equals(self._blockDigester.digest()):
					print('Block digest mismatch for record {}: recorded {} v calculated {}'.format(self._recordID, self._recordedBlockDigest.format(), self._recordedBlockDigest.format(self._blockDigester.digest())), file = sys.stderr)
					self._verificationFailed = True
			if self._payloadDigester and self._recordedPayloadDigest and self._recordType in (b'request', b'response'): #TODO: Support revisit
				if not self._recordedPayloadDigest.equals(self._payloadDigester.digest()):
					if self._recordedPayloadDigest.equals(self._brokenPayloadDigester.digest()):
						if not self._printedBrokenPayloadWarning:
							print('Warning: WARC uses incorrect payload digests without stripping the transfer encoding', file = sys.stderr)
							self._printedBrokenPayloadWarning = True
					else:
						print('Payload digest mismatch for record {}: recorded {} vs. calculated {} (calculated broken {})'.format(self._recordID, self._recordedPayloadDigest.format(), self._recordedPayloadDigest.format(self._payloadDigester.digest()), self._recordedPayloadDigest.format(self._brokenPayloadDigester.digest())), file = sys.stderr)
						self._verificationFailed = True
		elif type(event) is EndOfFile and self._verificationFailed:
			raise VerificationError('one or more errors encountered while verifying {}'.format(event.filename))


class DumpResponsesMode(ProcessMode):
	@classmethod
	def split_args(cls, args):
		if args[0] == '-m' or args[0] == '--meta':
			return (True,), args[1:]
		return (False,), args

	def __init__(self, withMeta):
		self._printEOR = False
		self._isResponse = False
		self._withMeta = withMeta
		if withMeta:
			self._recordID = None
			self._targetURI = None
			self._buffer = b''

	def _write(self, data):
		if not self._withMeta:
			sys.stdout.buffer.write(data)
			return

		buf = self._buffer + data
		lines = buf.split(b'\n')
		self._buffer = lines.pop() # Since there's an explicit `_write(b'\r\n')` at the end of the record, this implicitly resets the buffer as well
		for line in lines:
			sys.stdout.buffer.write(':'.join((self._filename, '-1', self._recordID, '<' + self._targetURI + '>', '')).encode('utf-8'))
			sys.stdout.buffer.write(line)
			sys.stdout.buffer.write(b'\n')

	def process_event(self, event):
		if type(event) is NewFile:
			self._filename = event.filename
			if ':' in self._filename:
				self._filename = '<' + self._filename + '>'
		elif type(event) is BeginOfRecord:
			warcContentType = next(x[1] for x in event.warcHeaders if x[0] == b'Content-Type')
			warcType = next(x[1] for x in event.warcHeaders if x[0] == b'WARC-Type')
			self._isResponse = warcContentType in (b'application/http;msgtype=response', b'application/http; msgtype=response') and warcType == b'response'
			self._printEOR = False
			if self._withMeta:
				# Both of these are URIs, and per RFC 3986, those can only contain ASCII characters.
				self._recordID = next(x[1] for x in event.warcHeaders if x[0] == b'WARC-Record-ID').decode('ascii')
				self._targetURI = next((x[1] for x in event.warcHeaders if x[0] == b'WARC-Target-URI'), b'').decode('ascii')
				self._buffer = b''
		elif type(event) is HTTPBodyChunk:
			if self._isResponse:
				self._printEOR = True
				self._write(event.data)
		elif type(event) is EndOfRecord:
			if self._printEOR:
				self._write(b'\r\n')


class COLOURS:
	RESET = b'\x1b[0m'
	GREEN = b'\x1b[0;32m'
	LIGHTGREEN = b'\x1b[1;32m'
	PURPLE = b'\x1b[0;35m'
	LIGHTPURPLE = b'\x1b[1;35m'
	RED = b'\x1b[0;31m'
	INVERTED = b'\x1b[7m'


class ColourMode(ProcessMode):
	def __init__(self):
		self._hadHttpStatusLine = False

	def _replace_esc(self, data):
		return data.replace(b'\x1b', COLOURS.INVERTED + b'ESC' + COLOURS.RESET)

	def _print_line(self, line, colour, withLF = True, colourOnlyBeforeColon = False):
		if colourOnlyBeforeColon:
			if b':' in line:
				offset = line.index(b':')
			else:
				offset = 0
		else:
			offset = len(line)
		if offset > 0:
			sys.stdout.buffer.write(colour)
			sys.stdout.buffer.write(self._replace_esc(line[:offset]))
			sys.stdout.buffer.write(COLOURS.RESET)
		sys.stdout.buffer.write(line[offset:])
		if withLF:
			sys.stdout.buffer.write(b'\n')

	def _print_data(self, data, colour, colourOnlyBeforeColon):
		later = False
		for line in data.split(b'\r\n'):
			if later:
				sys.stdout.buffer.write(b'\n')
			self._print_line(line, colour, withLF = False, colourOnlyBeforeColon = colourOnlyBeforeColon)
			later = True

	def process_event(self, event):
		if type(event) is BeginOfRecord:
			firstNewline = event.rawData.index(b'\r\n')
			self._print_line(event.rawData[:firstNewline], COLOURS.LIGHTGREEN)
			self._print_data(event.rawData[firstNewline + 2:], COLOURS.GREEN, True)
			sys.stdout.buffer.write(b'\n\n') # separator between header and block
			self._hadHttpStatusLine = False
		elif type(event) is WARCBlockChunk:
			if event.isHttpHeader is True:
				if not self._hadHttpStatusLine:
					firstNewline = event.data.index(b'\r\n')
					self._print_line(event.data[:firstNewline], COLOURS.LIGHTPURPLE)
					offset = firstNewline + 2
					self._hadHttpStatusLine = True
				else:
					offset = 0
				self._print_data(event.data[offset:], COLOURS.PURPLE, True)
			elif event.isHttpHeader is False:
				self._print_data(event.data, COLOURS.RED, False)
			elif event.isHttpHeader is None:
				sys.stdout.buffer.write(self._replace_esc(event.data))
		elif type(event) is EndOfRecord:
			sys.stdout.buffer.write(b'\n\n')


class ScrapeMode(ProcessMode):
	@classmethod
	def split_args(cls, args):
		if args[0] == '-u' or args[0] == '--urls':
			return (True,), args[1:]
		return (False,), args

	def __init__(self, urlsOnly):
		self._urlsOnly = urlsOnly

		assert wpull is not None, 'Scrape mode requires wpull and lxml'
		htmlParser = wpull.document.htmlparse.lxml_.HTMLParser()
		elementWalker = wpull.scraper.html.ElementWalker()
		scrapers = []
		scrapers.append(wpull.scraper.html.HTMLScraper(htmlParser, elementWalker))
		scrapers.append(wpull.scraper.css.CSSScraper())
		elementWalker.css_scraper = scrapers[-1]
		scrapers.append(wpull.scraper.javascript.JavaScriptScraper())
		elementWalker.javascript_scraper = scrapers[-1]
		scrapers.append(wpull.scraper.sitemap.SitemapScraper(htmlParser))
		self._scraper = wpull.scraper.base.DemuxDocumentScraper(scrapers)

		self._isResponse = None
		self._body = None
		self._recordURI = None
		self._statusCode = None
		self._statusReason = None
		if not self._urlsOnly:
			self._filename = None
			self._recordID = None

	def process_event(self, event):
		if type(event) is NewFile and not self._urlsOnly:
			self._filename = event.filename
		elif type(event) is BeginOfRecord:
			warcContentType = next(x[1] for x in event.warcHeaders if x[0] == b'Content-Type')
			warcType = next(x[1] for x in event.warcHeaders if x[0] == b'WARC-Type')
			self._isResponse = warcContentType in (b'application/http;msgtype=response', b'application/http; msgtype=response') and warcType == b'response'
			if self._isResponse:
				self._body = wpull.body.Body(file = tempfile.SpooledTemporaryFile(max_size = 10485760)) # Up to 10 MiB in memory
			self._printEOR = False
			if not self._urlsOnly:
				# Both of these are URIs, and per RFC 3986, those can only contain ASCII characters.
				self._recordID = next(x[1] for x in event.warcHeaders if x[0] == b'WARC-Record-ID').decode('ascii')
			self._recordURI = next((x[1] for x in event.warcHeaders if x[0] == b'WARC-Target-URI'), b'').decode('ascii')
		elif type(event) is HTTPHeaders and self._isResponse:
			assert len(event.headers[0]) == 1 and event.headers[0][0].startswith(b'HTTP/'), 'malformed HTTP response'
			_, statusCode, reason = event.headers[0][0].decode('ascii').split(' ', 2)
			self._statusCode = int(statusCode)
			self._statusReason = reason
		elif type(event) is HTTPBodyChunk and self._isResponse:
			self._body.write(event.data)
		elif type(event) is EndOfRecord and self._isResponse:
			request = wpull_protocol_http_request.Request(self._recordURI)
			response = wpull_protocol_http_request.Response(self._statusCode, self._statusReason)
			response.body = self._body
			response.body.seek(0)
			for scraper, scrapeResult in self._scraper.scrape_info(request, response).items():
				if not scrapeResult:
					continue
				for linkContext in scrapeResult.link_contexts:
					if self._urlsOnly:
						print(linkContext.link)
						continue
					o = {
						'filename': self._filename,
						'recordOffset': None,
						'recordID': self._recordID,
						'recordURI': self._recordURI,
						'linkType': linkContext.link_type.value if isinstance(linkContext.link_type, enum.Enum) else linkContext.link_type,
						'inline': bool(linkContext.inline), # Needs manual casting; https://github.com/ArchiveTeam/wpull/issues/458
						'linked': bool(linkContext.linked),
						'url': linkContext.link,
					}
					print(json.dumps(o))


def main():
	processorMap = {'verify': VerifyMode, 'dump-responses': DumpResponsesMode, 'colour': ColourMode, 'scrape': ScrapeMode}

	assert len(sys.argv) - 1 >= 2
	mode = sys.argv[1]
	assert mode in processorMap
	processorArgs, files = processorMap[mode].split_args(sys.argv[2:])
	assert files

	processor = processorMap[mode](*processorArgs)

	try:
		for f in files:
			if f.endswith('.warc.gz') or f.endswith('.warc.zst'):
				print(f'Warning: warc-tiny does not support decompressing WARCs like {f}. Please use zcat/zstdcat/zstdwarccat and pipe the decompressed stream into warc-tiny instead.', file = sys.stderr)
			print('Info: processing {}'.format(f), file = sys.stderr)
			processor.process_event(NewFile(f))
			if f == '-':
				f = sys.stdin.buffer
			for event in iter_warc(f):
					processor.process_event(event)
			processor.process_event(EndOfFile(f))
	except BrokenPipeError:
		return


if __name__ == '__main__':
	main()
