#!/usr/bin/env python
# Converts a raw Pixel ABL import into a more usable Ghidra analysis session.
# The script rebases the program, finds the Pixel function table when present,
# applies function names, and falls back to prologue scanning otherwise.

#@category Pixel

import re

import jarray

from ghidra.program.model.data import (
    CategoryPath,
    DataTypeConflictHandler,
    DWordDataType,
    Pointer64DataType,
    StructureDataType,
)
from ghidra.program.model.symbol import SourceType

try:
    INTEGER_TYPES = (int, long)
except NameError:
    INTEGER_TYPES = (int,)


BASE_ADDR = 0xFFFF0000F8800000
FUNC_TABLE_CATEGORY = CategoryPath("/pixel_loader")
FUNC_TABLE_ENTRY_TYPE = None
PROLOGUE_PATTERNS = (
    (0xFD, 0x7B, 0x01, None),
    (0xFD, 0x7B, 0xB8, None),
    (0xFD, 0x7B, 0xB9, None),
    (0xFD, 0x7B, 0xBB, None),
    (0xFD, 0x7B, 0xBA, None),
    (0xFD, 0x7B, 0xBE, None),
    (0xFD, 0x7B, 0xBC, None),
    (0xFD, 0x7B, 0xBD, None),
    (0xFD, 0x7B, 0xBF, None),
    (0xFF, 0xC3, 0x02, None),
    (0xFF, 0xC3, 0x00, None),
    (0xFF, 0x03, 0x03, None),
    (0xFF, 0x03, 0x01, None),
    (0xFF, 0x43, 0x01, None),
    (0xFF, 0x83, 0x02, None),
    (0xFF, 0x83, 0x01, None),
)
ABL_PATTERNS = (
    (0xD5, 0x38, 0x42, 0x5C),
    (0xD5, 0x38, 0x10, 0x09),
    (0xD5, 0x18, 0x10, 0x09),
)


def log(message):
    println("[pixel_loader] " + message)


def byte_value(value):
    if isinstance(value, INTEGER_TYPES):
        return value & 0xFF
    return ord(value)


def get_program_size():
    memory = currentProgram.getMemory()
    return int(memory.getMaxAddress().subtract(memory.getMinAddress()) + 1)


def get_bytes(offset, size):
    if offset < 0 or size < 0 or offset + size > FILE_SIZE:
        return None
    data = jarray.zeros(size, "b")
    image_base = currentProgram.getImageBase().getOffset()
    currentProgram.getMemory().getBytes(toAddr(image_base + offset), data)
    return data


def read_le(offset, size):
    data = get_bytes(offset, size)
    if data is None:
        return None
    value = 0
    for index in range(size):
        value |= byte_value(data[index]) << (index * 8)
    return value


def sanitize_name(name, fallback_offset):
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", name or "")
    cleaned = cleaned.strip("_")
    if not cleaned:
        cleaned = "sub_%X" % fallback_offset
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned


def create_label_safe(address, name):
    try:
        createLabel(address, name, True)
    except:
        pass


def create_function_safe(address, name):
    if not currentProgram.getMemory().contains(address):
        return False

    if not name:
        name = "sub_%X" % address.getOffset()

    disassemble(address)
    function = getFunctionAt(address)
    if function is None:
        try:
            function = createFunction(address, name)
        except:
            function = getFunctionAt(address)

    if function is not None:
        try:
            function.setName(name, SourceType.IMPORTED)
        except:
            create_label_safe(address, name)
        return True

    create_label_safe(address, name)
    return False


def create_structs():
    global FUNC_TABLE_ENTRY_TYPE
    manager = currentProgram.getDataTypeManager()

    func_entry = StructureDataType(FUNC_TABLE_CATEGORY, "func_table_entry", 0)
    func_entry.add(Pointer64DataType.dataType, 8, "func_pointer", None)
    func_entry.add(DWordDataType.dataType, 4, "func_size", None)
    func_entry.add(DWordDataType.dataType, 4, "name_offset", None)
    FUNC_TABLE_ENTRY_TYPE = manager.addDataType(
        func_entry,
        DataTypeConflictHandler.REPLACE_HANDLER,
    )


def looks_like_pixel_abl():
    header = get_bytes(0, min(FILE_SIZE, 0x70))
    if header is None:
        return False

    values = [byte_value(item) for item in header]
    for pattern in ABL_PATTERNS:
        matched = False
        for offset in range(0, max(len(values) - len(pattern) + 1, 0)):
            if tuple(values[offset : offset + len(pattern)]) == pattern:
                matched = True
                break
        if not matched:
            return False
    return True


def find_func_table():
    search_start = FILE_SIZE - int(FILE_SIZE * 0.2)
    if search_start < 0x10:
        search_start = 0x10
    search_start -= search_start % 4

    for offset in range(search_start, FILE_SIZE - 0x10, 4):
        monitor.checkCancelled()

        entry_value_le = read_le(offset, 8)
        if entry_value_le != BASE_ADDR:
            continue

        table_size = read_le(offset - 0xC, 4)
        if table_size is None or table_size <= 0 or table_size > 0x4000:
            continue

        table_end = offset + (table_size * 16)
        if table_end <= offset or table_end > FILE_SIZE:
            continue

        end_of_code = read_le(table_end - 0x10, 8)
        if end_of_code is None:
            continue
        if BASE_ADDR <= end_of_code <= BASE_ADDR + FILE_SIZE:
            return offset, end_of_code

    return None, None


def read_c_string(offset):
    if offset < 0 or offset >= FILE_SIZE:
        return None

    chars = []
    while offset < FILE_SIZE:
        value = read_le(offset, 1)
        if value is None or value == 0:
            break
        if 0x20 <= value <= 0x7E:
            chars.append(chr(value))
        else:
            chars.append("_")
        offset += 1

    return "".join(chars)


def resolve_func_table(func_table_offset):
    table_size = read_le(func_table_offset - 0xC, 4)
    if table_size is None:
        return 0

    address_table_end = func_table_offset + (table_size * 16)
    create_label_safe(toAddr(BASE_ADDR + func_table_offset), "pixel_func_table")
    create_label_safe(toAddr(BASE_ADDR + address_table_end), "pixel_func_names")

    resolved = 0
    for entry_index, entry_offset in enumerate(range(func_table_offset, address_table_end, 16)):
        monitor.checkCancelled()

        func_offset = read_le(entry_offset, 8)
        string_offset = read_le(entry_offset + 12, 4)
        if func_offset is None or string_offset is None:
            continue
        if func_offset < BASE_ADDR or func_offset >= BASE_ADDR + FILE_SIZE:
            continue
        if address_table_end + string_offset >= FILE_SIZE:
            continue

        func_name = read_c_string(address_table_end + string_offset)
        if not func_name:
            func_name = "sub_%X" % func_offset

        safe_name = sanitize_name(func_name, func_offset)
        entry_addr = toAddr(BASE_ADDR + entry_offset)
        if FUNC_TABLE_ENTRY_TYPE is not None:
            try:
                createData(entry_addr, FUNC_TABLE_ENTRY_TYPE)
            except:
                pass
        create_label_safe(entry_addr, "func_table_entry_%04d" % entry_index)
        if create_function_safe(toAddr(func_offset), safe_name):
            resolved += 1

    return resolved


def find_possible_code_end():
    zero_window = 0x230
    start = int(FILE_SIZE * 0.4)
    end = int(FILE_SIZE * 0.57)
    if end <= start or zero_window <= 0:
        return None

    block = get_bytes(start, end - start)
    if block is None:
        return None

    values = [byte_value(item) for item in block]
    for index in range(0, len(values) - zero_window + 1, 4):
        monitor.checkCancelled()
        if all(value == 0 for value in values[index : index + zero_window]):
            return start + index
    return None


def matches_prologue(values, offset, pattern):
    for index, expected in enumerate(pattern):
        if expected is None:
            continue
        if values[offset + index] != expected:
            return False
    return True


def find_code_by_prologue(start_offset, end_offset):
    span = end_offset - start_offset
    if span <= 0:
        return 0

    block = get_bytes(start_offset, span)
    if block is None:
        return 0

    values = [byte_value(item) for item in block]
    found = 0
    for offset in range(0, len(values) - 3, 4):
        monitor.checkCancelled()
        for pattern in PROLOGUE_PATTERNS:
            if matches_prologue(values, offset, pattern):
                if create_function_safe(
                    toAddr(BASE_ADDR + start_offset + offset),
                    "sub_%X" % (BASE_ADDR + start_offset + offset),
                ):
                    found += 1
                break
    return found


def ensure_image_base():
    if currentProgram.getImageBase().getOffset() == BASE_ADDR:
        return

    log("Rebasing program to 0x%X" % BASE_ADDR)
    currentProgram.setImageBase(toAddr(BASE_ADDR), True)


def main():
    signature_matches = looks_like_pixel_abl()
    if not signature_matches:
        log("warning: the current binary does not match the expected Pixel ABL signature")

    ensure_image_base()
    if signature_matches:
        create_structs()

    func_table_offset = None
    end_of_code = None
    if signature_matches:
        func_table_offset, end_of_code = find_func_table()

    if func_table_offset is not None:
        log("function table at 0x%X" % (BASE_ADDR + func_table_offset))
        create_label_safe(toAddr(end_of_code), "pixel_code_end")
        resolved = resolve_func_table(func_table_offset)
        log("resolved %d functions from the function table" % resolved)
        created = find_code_by_prologue(0, FILE_SIZE)
        log("identified %d additional function entry points by prologue scan" % created)
        return

    log("function table not found; falling back to code boundary and prologue detection")
    possible_code_end = find_possible_code_end()
    if possible_code_end is not None:
        create_label_safe(toAddr(BASE_ADDR + possible_code_end), "pixel_code_end")

    created = find_code_by_prologue(0, FILE_SIZE)
    log("identified %d possible function entry points by prologue scan" % created)


FILE_SIZE = get_program_size()
main()
