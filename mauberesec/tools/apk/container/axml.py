"""Minimal pure-python parser for Android binary XML (AXML).

Parses the compiled AndroidManifest.xml / network-security-config format:
string pool, start/end namespace, start/end element, CDATA. Attribute typed
values resolve STRING/INT/BOOLEAN/REFERENCE; everything else falls back to
the raw string. Pure data inspection — no code from the APK is executed.
"""

from __future__ import annotations

import struct
from typing import Any

RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
UTF8_FLAG = 1 << 8

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12
TYPE_REFERENCE = 0x01
NO_INDEX = 0xFFFFFFFF


class AxmlError(Exception):
    """The binary XML is malformed."""


class Element(dict[str, Any]):
    """Element dict with name/attrs/children/text convenience accessors."""

    def __init__(self, name: str) -> None:
        super().__init__(name=name, attrs={}, children=[], text="")
        self.attrs: dict[str, Any] = self["attrs"]
        self.children: list[Element] = self["children"]
        self.text: str = self["text"]

    def get_attr(self, name: str, default: Any = None) -> Any:
        return self.attrs.get(name, default)

    def find_all(self, name: str) -> list[Element]:
        found = [c for c in self.children if c["name"] == name]
        for child in self.children:
            found.extend(child.find_all(name))
        return found


def _parse_string_pool(chunk: bytes) -> list[str]:
    if len(chunk) < 28:
        raise AxmlError("String pool chunk too small.")
    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", chunk, 8
    )
    utf8 = bool(flags & UTF8_FLAG)
    offsets = struct.unpack_from(f"<{string_count}I", chunk, 28)
    strings: list[str] = []
    for offset in offsets:
        pos = strings_start + offset
        try:
            if utf8:
                char_count = chunk[pos]
                pos += 1
                if char_count & 0x80:
                    char_count = ((char_count & 0x7F) << 8) | chunk[pos]
                    pos += 1
                byte_len = chunk[pos]
                pos += 1
                if byte_len & 0x80:
                    byte_len = ((byte_len & 0x7F) << 8) | chunk[pos]
                    pos += 1
                strings.append(chunk[pos : pos + byte_len].decode("utf-8", "replace"))
            else:
                char_count = struct.unpack_from("<H", chunk, pos)[0]
                pos += 2
                if char_count & 0x8000:
                    hi = struct.unpack_from("<H", chunk, pos)[0]
                    pos += 2
                    char_count = ((char_count & 0x7FFF) << 16) | hi
                strings.append(chunk[pos : pos + char_count * 2].decode("utf-16-le", "replace"))
        except (IndexError, struct.error) as exc:
            raise AxmlError(f"Corrupt string pool entry: {exc}") from exc
    return strings


def _resolve_value(data_type: int, data: int, raw_value: int, strings: list[str]) -> Any:
    if data_type == TYPE_STRING:
        if data != NO_INDEX and data < len(strings):
            return strings[data]
        return ""
    if data_type == TYPE_INT_BOOLEAN:
        return bool(data)
    if data_type == TYPE_INT_DEC:
        return data
    if data_type == TYPE_REFERENCE:
        return f"@{(data & 0x7FFFFFFF):#x}"
    if raw_value != NO_INDEX and raw_value < len(strings):
        return strings[raw_value]
    return data


def parse_axml(data: bytes) -> Element:
    """Parse a binary XML document and return the root Element."""
    if len(data) < 8:
        raise AxmlError("Document too small.")
    doc_type, _hdr_size, doc_size = struct.unpack_from("<HHI", data, 0)
    if doc_type != 0x0003:
        raise AxmlError(f"Not a binary XML document (type {doc_type:#x}).")
    if doc_size > len(data):
        raise AxmlError("Declared document size exceeds available data.")

    pos = 8
    strings: list[str] = []
    root: Element | None = None
    stack: list[Element] = []

    while pos + 8 <= doc_size and pos + 8 <= len(data):
        chunk_type, _chunk_hdr, chunk_size = struct.unpack_from("<HHI", data, pos)
        if chunk_size < 8 or pos + chunk_size > len(data):
            raise AxmlError("Bad chunk size.")
        chunk = data[pos : pos + chunk_size]
        pos += chunk_size

        if chunk_type == RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(chunk)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            if len(chunk) < 36:
                raise AxmlError("Start-element chunk too small.")
            name_idx = struct.unpack_from("<I", chunk, 20)[0]
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", chunk, 24)
            if attr_size < 20:
                raise AxmlError("Bad attribute size.")
            element = Element(strings[name_idx] if name_idx < len(strings) else f"?{name_idx}")
            for i in range(attr_count):
                # attrStart is relative to the attrExt structure, which
                # begins after the generic header (8) + node header (8).
                off = 16 + attr_start + i * attr_size
                if off + 20 > len(chunk):
                    raise AxmlError("Attribute out of bounds.")
                _ns, name_idx2, raw_value, _vsize, _res0, data_type, attr_data = struct.unpack_from(
                    "<IIIHBBI", chunk, off
                )
                attr_name = strings[name_idx2] if name_idx2 < len(strings) else f"?{name_idx2}"
                element.attrs[attr_name] = _resolve_value(data_type, attr_data, raw_value, strings)
            if stack:
                stack[-1].children.append(element)
            stack.append(element)
            if root is None:
                root = element
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        elif chunk_type == RES_XML_CDATA_TYPE:
            if stack:
                data_idx = struct.unpack_from("<I", chunk, 8)[0]
                if data_idx < len(strings):
                    stack[-1].text += strings[data_idx]

    if root is None:
        raise AxmlError("No root element found.")
    return root
