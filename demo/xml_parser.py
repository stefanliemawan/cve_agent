"""Mirrors CVE-2021-28957 / classic XXE: lxml parsing with entity resolution on.

Weakness description: "XML External Entity (XXE) reference in untrusted document"
"""
from lxml import etree


# VULNERABLE: resolve_entities=True (default) + load_dtd=True allows <!ENTITY xxe SYSTEM "file:///etc/passwd">
_unsafe_parser = etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)


def parse_feed(raw_bytes):
    root = etree.fromstring(raw_bytes, parser=_unsafe_parser)
    return {child.tag: child.text for child in root}


# VULNERABLE: requests fetch + lxml — also enables SSRF when `url` is user-controlled
import requests  # noqa: E402


def fetch_and_parse(url):
    resp = requests.get(url, verify=False)  # CVE-2018-18074 + TLS verify disabled
    return parse_feed(resp.content)


# SAFE reference (after fix):
# _safe_parser = etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
# def parse_feed_safe(raw_bytes):
#     root = etree.fromstring(raw_bytes, parser=_safe_parser)
#     ...
