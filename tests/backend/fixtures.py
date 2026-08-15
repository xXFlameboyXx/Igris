"""Safe synthetic binary fixtures for Phase 1 tests."""

from struct import pack


def minimal_pe32_fixture() -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pack("<I", 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    data[coff : coff + 20] = pack(
        "<HHIIIHH",
        0x014C,
        1,
        1_700_000_000,
        0,
        0,
        224,
        0x010F,
    )
    optional = coff + 20
    data[optional : optional + 96] = pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        14,
        0,
        0x200,
        0,
        0,
        0x1000,
        0x1000,
        0,
        0x400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    section = optional + 224
    data[section : section + 40] = pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        1,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[0x200] = 0xC3
    return bytes(data)


def malformed_pe_fixture() -> bytes:
    data = bytearray(64)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pack("<I", 0xFFFF)
    return bytes(data)


def minimal_elf64_fixture() -> bytes:
    text = b"\xc3"
    shstrtab = b"\0.text\0.shstrtab\0"
    text_offset = 0x100
    shstrtab_offset = 0x110
    section_header_offset = 0x130
    data = bytearray(section_header_offset + 64 * 3)

    data[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    data[16:64] = pack(
        "<HHIQQQIHHHHHH",
        2,
        0x3E,
        1,
        0x400000,
        0,
        section_header_offset,
        0,
        64,
        0,
        0,
        64,
        3,
        2,
    )
    data[text_offset : text_offset + len(text)] = text
    data[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    section_one = section_header_offset + 64
    data[section_one : section_one + 64] = pack(
        "<IIQQQQIIQQ",
        1,
        1,
        0x6,
        0x400000,
        text_offset,
        len(text),
        0,
        0,
        16,
        0,
    )
    section_two = section_header_offset + 128
    data[section_two : section_two + 64] = pack(
        "<IIQQQQIIQQ",
        7,
        3,
        0,
        0,
        shstrtab_offset,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )
    return bytes(data)


def malformed_elf_fixture() -> bytes:
    return b"\x7fELF\x02\x01"


def static_suspicious_pe_fixture() -> bytes:
    data = bytearray(0x900)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pack("<I", 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    data[coff : coff + 20] = pack(
        "<HHIIIHH",
        0x014C,
        1,
        1_700_000_000,
        0,
        0,
        224,
        0x010F,
    )
    optional = coff + 20
    data[optional : optional + 96] = pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        14,
        0,
        0x600,
        0,
        0,
        0x1000,
        0x1000,
        0,
        0x400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x3000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    data[optional + 96 + 16 : optional + 96 + 24] = pack("<II", 0x1500, 0x40)
    section = optional + 224
    data[section : section + 40] = pack(
        "<8sIIIIIIHHI",
        b".packed\0",
        0x800,
        0x1000,
        0x600,
        0x200,
        0,
        0,
        0,
        0,
        0xE0000020,
    )
    for index in range(0x600):
        data[0x200 + index] = (index * 73 + 19) % 256
    strings = (
        b"http://example.test/path\0"
        b"192.0.2.15\0"
        b"HKCU\\Software\\IgrisTest\0"
        b"powershell.exe\0"
        b"InternetOpenA\0"
        b"VirtualAlloc\0"
        b"CreateRemoteThread\0"
        b"benign test credential keyword\0"
    )
    data[0x620 : 0x620 + len(strings)] = strings
    data[0x700:0x740] = bytes(range(64))
    data[0x800:0x900] = b"OVERLAY" * 36 + b"END!"
    return bytes(data)


def reverse_x86_pe_fixture() -> bytes:
    data = bytearray(0x700)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pack("<I", 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    data[coff : coff + 20] = pack(
        "<HHIIIHH",
        0x014C,
        1,
        1_700_000_000,
        0,
        0,
        224,
        0x010F,
    )
    optional = coff + 20
    data[optional : optional + 96] = pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        14,
        0,
        0x400,
        0,
        0,
        0x1000,
        0x1000,
        0,
        0x400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    section = optional + 224
    data[section : section + 40] = pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0x400,
        0x1000,
        0x400,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    entry = bytes.fromhex("5589e5b800124000bb30124000e80e00000083f801750390eb0190c3")
    helper = bytes.fromhex("5589e5b8010000005dc3")
    data[0x200 : 0x200 + len(entry)] = entry
    data[0x220 : 0x220 + len(helper)] = helper
    data[0x400 : 0x400 + 23] = b"HKCU\\Software\\Igris\0"
    data[0x430 : 0x430 + 13] = b"VirtualAlloc\0"
    return bytes(data)


def unsupported_arm64_pe_fixture() -> bytes:
    data = bytearray(minimal_pe32_fixture())
    data[0x84:0x86] = pack("<H", 0xAA64)
    return bytes(data)
