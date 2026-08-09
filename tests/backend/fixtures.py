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
    text = b"\xC3"
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
