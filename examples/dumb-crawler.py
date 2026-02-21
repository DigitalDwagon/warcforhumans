import argparse

import requests
from urllib3.exceptions import InsecureRequestWarning

import warcforhumans.capture.http as capture
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from warcforhumans.api import WARCWriter
from warcforhumans.compression import ZSTDCompressor


def dumb_crawler(seed_url, max_depth=1, max_urls=-1):
    writer = WARCWriter("dumbcrawler-$date-$serial-$number",
                        compressor=ZSTDCompressor(level=11),
                        software="dumb-crawler"
                        )

    capture.warc_writer = writer

    # Suppress "insecure request" warning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    urls_to_visit = [(seed_url, 0)]
    req_count = 0

    while urls_to_visit:
        if max_urls > 0 and req_count >= max_urls:
            break

        url, depth = urls_to_visit.pop(0)
        if depth > max_depth:
            print(f"\tToo much depth: {depth}/{max_depth} {url}")
            continue



        r = requests.get(url, timeout=5, verify=False)
        print(f"{req_count}={r.status_code} {url}")
        req_count += 1

        soup = BeautifulSoup(r.text, 'html.parser')

        for tag in soup.find_all(['a', 'img', 'link', 'script']):
            if tag.name == 'a' and tag.get('href'):
                new_url = urljoin(url, tag['href'])
            elif tag.name == 'img' and tag.get('src'):
                new_url = urljoin(url, tag['src'])
            elif tag.name == 'link' and tag.get('href'):
                new_url = urljoin(url, tag['href'])
            elif tag.name == 'script' and tag.get('src'):
                new_url = urljoin(url, tag['src'])
            else:
                continue

            if not new_url.startswith("http") and not new_url.startswith("https"):
                continue
            if not "archiveteam.org" in new_url:
                continue
            #print(f"\t{depth + 1}, {new_url}")
            urls_to_visit.append((new_url, depth + 1))

    writer.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-depth", default=999, dest="max_depth", help="Max depth to crawl, starting from seed.")
    parser.add_argument("--max-urls", default=-1,  dest="max_urls", help="Max number of urls to crawl")
    parser.add_argument("--url", help="Seed URL to start crawling from")
    args = parser.parse_args()
    dumb_crawler(args.url, int(args.max_depth), int(args.max_urls))

if __name__ == "__main__":
    main()