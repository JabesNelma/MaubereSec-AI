"""Minimal AXML encoder for test fixtures (mirrors the aapt binary format)."""

import struct


def encode_string_pool(strings: list[str]) -> bytes:
    encoded = []
    for s in strings:
        b = s.encode("utf-16-le")
        encoded.append(struct.pack("<H", len(s)) + b + b"\x00\x00")
    strings_start = 28 + 4 * len(strings)
    size = strings_start + sum(len(e) for e in encoded)
    header = struct.pack(
        "<HHIIIIII",
        0x0001,
        28,
        size,
        len(strings),
        0,
        0,
        strings_start,
        0,
    )
    offsets = b"".join(
        struct.pack("<I", sum(len(e) for e in encoded[:i])) for i in range(len(strings))
    )
    return header + offsets + b"".join(encoded)


def encode_start_element(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
    """attrs: list of (name_idx, data_type, data)."""
    attr_start, attr_size = 0x14, 0x14
    body = struct.pack("<II", 0xFFFFFFFF, name_idx)  # ns, name
    body += struct.pack(
        "<HHHHHH",
        attr_start,
        attr_size,
        len(attrs),
        0,
        0,
        0,
    )
    for a_name, dtype, data in attrs:
        body += struct.pack(
            "<IIIHBBI",
            0xFFFFFFFF,
            a_name,
            0xFFFFFFFF,
            8,
            0,
            dtype,
            data,
        )
    size = 16 + len(body)
    return struct.pack("<HHI", 0x0102, 16, size) + struct.pack("<II", 1, 0xFFFFFFFF) + body


def encode_end_element(name_idx: int) -> bytes:
    # generic header(8) + line(4) + comment(4) + ns(4) + name(4) = 24 bytes
    return (
        struct.pack("<HHI", 0x0103, 16, 24)
        + struct.pack("<II", 1, 0xFFFFFFFF)
        + struct.pack("<II", 0xFFFFFFFF, name_idx)
    )


def encode_axml(strings: list[str], chunks: list[bytes]) -> bytes:
    pool = encode_string_pool(strings)
    body = pool + b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


# String type 0x03, int 0x10, bool 0x12.
STRING, INT, BOOL = 0x03, 0x10, 0x12


def sample_manifest_axml() -> bytes:
    """A manifest with: package, debuggable, cleartext, CAMERA permission,
    exported unprotected activity, targetSdk 21."""
    strings = [
        "manifest",  # 0
        "package",  # 1
        "com.example.vuln",  # 2
        "versionName",  # 3
        "1.0",  # 4
        "application",  # 5
        "debuggable",  # 6
        "usesCleartextTraffic",  # 7
        "uses-permission",  # 8
        "name",  # 9
        "android.permission.CAMERA",  # 10
        "activity",  # 11
        "exported",  # 12
        "uses-sdk",  # 13
        "targetSdkVersion",  # 14
        "MainActivity",  # 15
    ]
    chunks = [
        encode_start_element(0, [(1, STRING, 2), (3, STRING, 4)]),
        # <application debuggable=true usesCleartextTraffic=true>
        encode_start_element(5, [(6, BOOL, 0xFFFFFFFF), (7, BOOL, 0xFFFFFFFF)]),
        # <uses-permission name=CAMERA/>
        encode_start_element(8, [(9, STRING, 10)]),
        encode_end_element(8),
        # <activity name=MainActivity exported=true/>
        encode_start_element(11, [(9, STRING, 15), (12, BOOL, 0xFFFFFFFF)]),
        encode_end_element(11),
        encode_end_element(5),
        # <uses-sdk targetSdkVersion=21/>
        encode_start_element(13, [(14, INT, 21)]),
        encode_end_element(13),
        encode_end_element(0),
    ]
    return encode_axml(strings, chunks)


def clean_manifest_axml() -> bytes:
    strings = [
        "manifest",
        "package",
        "com.example.clean",
        "versionName",
        "2.0",
        "application",
        "uses-sdk",
        "targetSdkVersion",
    ]
    chunks = [
        encode_start_element(0, [(1, STRING, 2), (3, STRING, 4)]),
        encode_start_element(5, []),
        encode_end_element(5),
        encode_start_element(6, [(7, INT, 34)]),
        encode_end_element(6),
        encode_end_element(0),
    ]
    return encode_axml(strings, chunks)
