#!/usr/bin/env python3
"""
DashO Deobfuscator — Cracks XOR string encryption used by PreEmptive DashO obfuscator.

Parses Java .class file bytecode to find encrypted string decrypt calls:
    ldc "encrypted_string"
    bipush/sipush xor_key
    invokestatic ClassName.d(String, int) -> String

Then XOR-decrypts each string and outputs the results.

Usage:
    python deobfuscate_dasho.py <jar_or_class_file> [--output <dir>] [--patch]
"""

import struct
import zipfile
import sys
import os
import io
import re
import json
import shutil
from pathlib import Path

# ── Constant pool tag types ──
CONSTANT_Utf8 = 1
CONSTANT_Integer = 3
CONSTANT_Float = 4
CONSTANT_Long = 5
CONSTANT_Double = 6
CONSTANT_Class = 7
CONSTANT_String = 8
CONSTANT_Fieldref = 9
CONSTANT_Methodref = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_NameAndType = 12
CONSTANT_MethodHandle = 15
CONSTANT_MethodType = 16
CONSTANT_Dynamic = 17
CONSTANT_InvokeDynamic = 18
CONSTANT_Module = 19
CONSTANT_Package = 20

# Bytecode opcodes we care about
OP_NOP = 0x00
OP_ICONST_M1 = 0x02
OP_ICONST_0 = 0x03
OP_ICONST_1 = 0x04
OP_ICONST_2 = 0x05
OP_ICONST_3 = 0x06
OP_ICONST_4 = 0x07
OP_ICONST_5 = 0x08
OP_BIPUSH = 0x10
OP_SIPUSH = 0x11
OP_LDC = 0x12
OP_LDC_W = 0x13
OP_INVOKESTATIC = 0xB8
OP_INVOKEVIRTUAL = 0xB6
OP_INVOKESPECIAL = 0xB7
OP_INVOKEINTERFACE = 0xB9
OP_INVOKEDYNAMIC = 0xBA
OP_PUTSTATIC = 0xB3
OP_GETSTATIC = 0xB2
OP_PUTFIELD = 0xB5
OP_GETFIELD = 0xB4
OP_NEW = 0xBB
OP_ANEWARRAY = 0xBD
OP_CHECKCAST = 0xC0
OP_INSTANCEOF = 0xC1
OP_MULTIANEWARRAY = 0xC5
OP_WIDE = 0xC4
OP_TABLESWITCH = 0xAA
OP_LOOKUPSWITCH = 0xAB
OP_GOTO_W = 0xC8
OP_JSR_W = 0xC9
OP_ILOAD = 0x15
OP_LLOAD = 0x16
OP_FLOAD = 0x17
OP_DLOAD = 0x18
OP_ALOAD = 0x19
OP_ISTORE = 0x36
OP_LSTORE = 0x37
OP_FSTORE = 0x38
OP_DSTORE = 0x39
OP_ASTORE = 0x3A
OP_RET = 0xA9
OP_IINC = 0x84
OP_NEWARRAY = 0xBC
OP_IF_ICMPEQ = 0x9F
OP_IF_ICMPNE = 0xA0
OP_IF_ICMPLT = 0xA1
OP_IF_ICMPGE = 0xA2
OP_IF_ICMPGT = 0xA3
OP_IF_ICMPLE = 0xA4
OP_IF_ACMPEQ = 0xA5
OP_IF_ACMPNE = 0xA6
OP_GOTO = 0xA7
OP_JSR = 0xA8
OP_IFNULL = 0xC6
OP_IFNONNULL = 0xC7
OP_IFEQ = 0x99
OP_IFNE = 0x9A
OP_IFLT = 0x9B
OP_IFGE = 0x9C
OP_IFGT = 0x9D
OP_IFLE = 0x9E

# Size of fixed-length opcodes (those not handled specially)
# Most opcodes are 1 byte. Those with operands are handled in the scanner.


def xor_decrypt(encrypted, key):
    """Simple XOR decrypt: each char ^ key (native method)."""
    key = key & 0xFFFF
    return ''.join(chr(ord(c) ^ key) for c in encrypted)


def indexOf_decrypt(encrypted, key):
    """DashO indexOf decrypt: char[i] ^ ((key+i) & 0x5F), key increments each char."""
    chars = list(encrypted)
    k = key
    for i in range(len(chars)):
        chars[i] = chr(ord(chars[i]) ^ (k & 0x5F))
        k += 1
    return ''.join(chars)


class ConstantPool:
    """Parse and query a Java class file constant pool."""

    def __init__(self, data, offset):
        self.entries = [None]  # 1-indexed
        self.raw = data
        count = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        i = 1
        while i < count:
            tag = data[offset]
            offset += 1
            if tag == CONSTANT_Utf8:
                length = struct.unpack_from('>H', data, offset)[0]
                offset += 2
                try:
                    value = data[offset:offset + length].decode('utf-8', errors='replace')
                except Exception:
                    value = data[offset:offset + length].decode('latin-1')
                self.entries.append(('Utf8', value))
                offset += length
            elif tag == CONSTANT_Integer:
                value = struct.unpack_from('>i', data, offset)[0]
                self.entries.append(('Integer', value))
                offset += 4
            elif tag == CONSTANT_Float:
                value = struct.unpack_from('>f', data, offset)[0]
                self.entries.append(('Float', value))
                offset += 4
            elif tag == CONSTANT_Long:
                value = struct.unpack_from('>q', data, offset)[0]
                self.entries.append(('Long', value))
                offset += 8
                i += 1
                self.entries.append(None)  # longs take 2 slots
            elif tag == CONSTANT_Double:
                value = struct.unpack_from('>d', data, offset)[0]
                self.entries.append(('Double', value))
                offset += 8
                i += 1
                self.entries.append(None)  # doubles take 2 slots
            elif tag == CONSTANT_Class:
                idx = struct.unpack_from('>H', data, offset)[0]
                self.entries.append(('Class', idx))
                offset += 2
            elif tag == CONSTANT_String:
                idx = struct.unpack_from('>H', data, offset)[0]
                self.entries.append(('String', idx))
                offset += 2
            elif tag in (CONSTANT_Fieldref, CONSTANT_Methodref, CONSTANT_InterfaceMethodref):
                class_idx = struct.unpack_from('>H', data, offset)[0]
                nat_idx = struct.unpack_from('>H', data, offset + 2)[0]
                tag_name = {9: 'Fieldref', 10: 'Methodref', 11: 'InterfaceMethodref'}[tag]
                self.entries.append((tag_name, class_idx, nat_idx))
                offset += 4
            elif tag == CONSTANT_NameAndType:
                name_idx = struct.unpack_from('>H', data, offset)[0]
                desc_idx = struct.unpack_from('>H', data, offset + 2)[0]
                self.entries.append(('NameAndType', name_idx, desc_idx))
                offset += 4
            elif tag == CONSTANT_MethodHandle:
                kind = data[offset]
                idx = struct.unpack_from('>H', data, offset + 1)[0]
                self.entries.append(('MethodHandle', kind, idx))
                offset += 3
            elif tag == CONSTANT_MethodType:
                idx = struct.unpack_from('>H', data, offset)[0]
                self.entries.append(('MethodType', idx))
                offset += 2
            elif tag in (CONSTANT_Dynamic, CONSTANT_InvokeDynamic):
                bootstrap = struct.unpack_from('>H', data, offset)[0]
                nat_idx = struct.unpack_from('>H', data, offset + 2)[0]
                tag_name = 'Dynamic' if tag == CONSTANT_Dynamic else 'InvokeDynamic'
                self.entries.append((tag_name, bootstrap, nat_idx))
                offset += 4
            elif tag == CONSTANT_Module:
                idx = struct.unpack_from('>H', data, offset)[0]
                self.entries.append(('Module', idx))
                offset += 2
            elif tag == CONSTANT_Package:
                idx = struct.unpack_from('>H', data, offset)[0]
                self.entries.append(('Package', idx))
                offset += 2
            else:
                raise ValueError(f"Unknown constant pool tag {tag} at offset {offset - 1}")
            i += 1
        self.end_offset = offset

    def get_utf8(self, idx):
        if idx < 1 or idx >= len(self.entries) or self.entries[idx] is None:
            return None
        entry = self.entries[idx]
        if entry[0] == 'Utf8':
            return entry[1]
        return None

    def get_string(self, idx):
        if idx < 1 or idx >= len(self.entries) or self.entries[idx] is None:
            return None
        entry = self.entries[idx]
        if entry[0] == 'String':
            return self.get_utf8(entry[1])
        return None

    def get_class_name(self, idx):
        if idx < 1 or idx >= len(self.entries) or self.entries[idx] is None:
            return None
        entry = self.entries[idx]
        if entry[0] == 'Class':
            return self.get_utf8(entry[1])
        return None

    def get_methodref(self, idx):
        """Returns (class_name, method_name, descriptor) or None."""
        if idx < 1 or idx >= len(self.entries) or self.entries[idx] is None:
            return None
        entry = self.entries[idx]
        if entry[0] not in ('Methodref', 'InterfaceMethodref'):
            return None
        class_name = self.get_class_name(entry[1])
        if entry[2] < 1 or entry[2] >= len(self.entries):
            return None
        nat = self.entries[entry[2]]
        if nat is None or nat[0] != 'NameAndType':
            return None
        method_name = self.get_utf8(nat[1])
        descriptor = self.get_utf8(nat[2])
        return (class_name, method_name, descriptor)

    def find_decrypt_methodrefs(self, decrypt_class_names=None):
        """Find all methodref indices that match the decrypt signature: (Ljava/lang/String;I)Ljava/lang/String;
        If decrypt_class_names is provided, only match refs targeting those classes."""
        decrypt_refs = set()
        for i, entry in enumerate(self.entries):
            if entry is None:
                continue
            if entry[0] in ('Methodref', 'InterfaceMethodref'):
                info = self.get_methodref(i)
                if info and info[2] == '(Ljava/lang/String;I)Ljava/lang/String;':
                    if decrypt_class_names is None or info[0] in decrypt_class_names:
                        decrypt_refs.add(i)
        return decrypt_refs


def parse_class_header(data):
    """Parse class file up to and including the class name. Returns (cp, this_class_name, offset_after_interfaces)."""
    if data[:4] != b'\xCA\xFE\xBA\xBE':
        return None, None, None

    # version
    offset = 8
    cp = ConstantPool(data, offset)
    offset = cp.end_offset

    # access flags, this_class, super_class
    access_flags = struct.unpack_from('>H', data, offset)[0]
    this_class = struct.unpack_from('>H', data, offset + 2)[0]
    super_class = struct.unpack_from('>H', data, offset + 4)[0]
    offset += 6

    class_name = cp.get_class_name(this_class)

    # interfaces
    iface_count = struct.unpack_from('>H', data, offset)[0]
    offset += 2 + iface_count * 2

    return cp, class_name, offset


def skip_fields_or_methods(data, offset, count):
    """Skip field_info or method_info structures, return new offset."""
    for _ in range(count):
        # access_flags, name_index, descriptor_index
        offset += 6
        # attributes
        attr_count = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        for _ in range(attr_count):
            # attr name index + length
            attr_len = struct.unpack_from('>I', data, offset + 2)[0]
            offset += 6 + attr_len
    return offset


def scan_class_for_decrypted_strings(data, decrypt_class_names=None, indexof_class_names=None):
    """
    Parse a .class file, find all encrypted string decrypt calls, and return decrypted strings.
    Returns: (class_name, [(method_name, encrypted, key, decrypted, mref), ...])
    decrypt_class_names: classes with native XOR d() method
    indexof_class_names: classes with indexOf-style decrypt (char ^ ((key+i) & 0x5F))
    """
    if len(data) < 10 or data[:4] != b'\xCA\xFE\xBA\xBE':
        return None, []

    try:
        offset = 8
        cp = ConstantPool(data, offset)
        offset = cp.end_offset
    except Exception:
        return None, []

    class_name = None
    results = []
    try:
        # access flags, this_class, super_class
        this_class_idx = struct.unpack_from('>H', data, offset + 2)[0]
        offset += 6

        class_name = cp.get_class_name(this_class_idx)

        # interfaces
        iface_count = struct.unpack_from('>H', data, offset)[0]
        offset += 2 + iface_count * 2

        # fields - skip
        field_count = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        for _ in range(field_count):
            offset += 6
            attr_count = struct.unpack_from('>H', data, offset)[0]
            offset += 2
            for _ in range(attr_count):
                attr_len = struct.unpack_from('>I', data, offset + 2)[0]
                offset += 6 + attr_len

        # methods - parse with Code attributes
        method_count = struct.unpack_from('>H', data, offset)[0]
        offset += 2

        # Find which CP indices are decrypt method refs
        all_decrypt_names = set()
        if decrypt_class_names:
            all_decrypt_names.update(decrypt_class_names)
        if indexof_class_names:
            all_decrypt_names.update(indexof_class_names)
        decrypt_refs = cp.find_decrypt_methodrefs(all_decrypt_names if all_decrypt_names else None)

        # Find the "Code" utf8 index
        code_utf8_indices = set()
        for i, entry in enumerate(cp.entries):
            if entry is not None and entry[0] == 'Utf8' and entry[1] == 'Code':
                code_utf8_indices.add(i)

        for _ in range(method_count):
            if offset + 8 > len(data):
                break
            try:
                m_access = struct.unpack_from('>H', data, offset)[0]
                m_name_idx = struct.unpack_from('>H', data, offset + 2)[0]
                m_desc_idx = struct.unpack_from('>H', data, offset + 4)[0]
                offset += 6
                m_attr_count = struct.unpack_from('>H', data, offset)[0]
                offset += 2

                method_name = cp.get_utf8(m_name_idx) or f"method_{m_name_idx}"

                for _ in range(m_attr_count):
                    if offset + 6 > len(data):
                        break
                    a_name_idx = struct.unpack_from('>H', data, offset)[0]
                    a_len = struct.unpack_from('>I', data, offset + 2)[0]
                    a_start = offset + 6

                    if a_name_idx in code_utf8_indices and a_len >= 12:
                        # Code attribute: max_stack(2) + max_locals(2) + code_length(4) + code(N) + ...
                        if a_start + 8 <= len(data):
                            code_len = struct.unpack_from('>I', data, a_start + 4)[0]
                            code_start = a_start + 8
                            if code_start + code_len <= len(data):
                                code = data[code_start:code_start + code_len]
                                found = scan_bytecode(code, cp, decrypt_refs, method_name,
                                                      decrypt_class_names, indexof_class_names)
                                results.extend(found)

                    offset = a_start + a_len
            except (struct.error, IndexError):
                # Malformed method — can't determine correct offset, stop scanning
                break

        return class_name, results
    except (struct.error, IndexError):
        # Truncated or malformed class file
        return class_name if class_name else None, results


def scan_bytecode(code, cp, decrypt_refs, method_name,
                  native_decrypt_classes=None, indexof_decrypt_classes=None):
    """
    Scan bytecode for the pattern:
        ldc/ldc_w <string>
        bipush/sipush/iconst/ldc <int key>
        invokestatic <decrypt_methodref>

    Returns list of (method_name, encrypted, key, decrypted, mref)
    """
    results = []
    length = len(code)

    # We'll track recent instructions as we scan
    # Each entry: (opcode, value, position)
    # For ldc: value = cp index
    # For push: value = int value

    recent = []  # stack of recent (type, value) — type is 'string' or 'int'

    pos = 0
    while 0 <= pos < length:
        op = code[pos]

        if op == OP_LDC:
            if pos + 1 < length:
                idx = code[pos + 1]
                s = cp.get_string(idx)
                if s is not None:
                    recent.append(('string', s))
                else:
                    # Check if it's an Integer constant (key loaded via ldc)
                    entry = cp.entries[idx] if idx < len(cp.entries) else None
                    if entry and entry[0] == 'Integer':
                        recent.append(('int', entry[1]))
                    else:
                        recent.append(('other', None))
                pos += 2
            else:
                pos += 1
        elif op == OP_LDC_W:
            if pos + 2 < length:
                idx = struct.unpack_from('>H', code, pos + 1)[0]
                s = cp.get_string(idx)
                if s is not None:
                    recent.append(('string', s))
                else:
                    entry = cp.entries[idx] if idx < len(cp.entries) else None
                    if entry and entry[0] == 'Integer':
                        recent.append(('int', entry[1]))
                    else:
                        recent.append(('other', None))
                pos += 3
            else:
                pos += 1
        elif op == OP_BIPUSH:
            if pos + 1 < length:
                val = struct.unpack_from('>b', code, pos + 1)[0]  # signed byte
                recent.append(('int', val))
                pos += 2
            else:
                pos += 1
        elif op == OP_SIPUSH:
            if pos + 2 < length:
                val = struct.unpack_from('>h', code, pos + 1)[0]  # signed short
                recent.append(('int', val))
                pos += 3
            else:
                pos += 1
        elif OP_ICONST_M1 <= op <= OP_ICONST_5:
            val = op - OP_ICONST_0  # -1 to 5
            recent.append(('int', val))
            pos += 1
        elif op == OP_INVOKESTATIC:
            if pos + 2 < length:
                idx = struct.unpack_from('>H', code, pos + 1)[0]
                if idx in decrypt_refs and len(recent) >= 2:
                    int_item = recent[-1]
                    str_item = recent[-2]
                    if str_item[0] == 'string' and int_item[0] == 'int':
                        encrypted = str_item[1]
                        key = int_item[1]
                        mref = cp.get_methodref(idx)
                        # Choose decrypt algorithm based on target class
                        target_class = mref[0] if mref else None
                        if indexof_decrypt_classes and target_class in indexof_decrypt_classes:
                            decrypted = indexOf_decrypt(encrypted, key)
                        else:
                            decrypted = xor_decrypt(encrypted, key)
                        results.append((method_name, encrypted, key, decrypted, mref))
                recent.append(('other', None))
                pos += 3
            else:
                pos += 1
        elif op in (OP_INVOKEVIRTUAL, OP_INVOKESPECIAL):
            recent.append(('other', None))
            pos += 3
        elif op == OP_INVOKEINTERFACE:
            recent.append(('other', None))
            pos += 5
        elif op == OP_INVOKEDYNAMIC:
            recent.append(('other', None))
            pos += 5
        elif op in (OP_GETSTATIC, OP_PUTSTATIC, OP_GETFIELD, OP_PUTFIELD):
            if op in (OP_GETSTATIC, OP_GETFIELD):
                recent.append(('other', None))
            pos += 3
        elif op in (OP_NEW, OP_ANEWARRAY, OP_CHECKCAST, OP_INSTANCEOF):
            if op == OP_NEW:
                recent.append(('other', None))
            pos += 3
        elif op == OP_MULTIANEWARRAY:
            pos += 4
        elif op == OP_NEWARRAY:
            pos += 2
        elif op in (OP_ILOAD, OP_LLOAD, OP_FLOAD, OP_DLOAD, OP_ALOAD,
                     OP_ISTORE, OP_LSTORE, OP_FSTORE, OP_DSTORE, OP_ASTORE, OP_RET):
            if op in (OP_ILOAD, OP_LLOAD, OP_FLOAD, OP_DLOAD, OP_ALOAD):
                recent.append(('other', None))
            pos += 2
        elif op == OP_IINC:
            pos += 3
        elif op == OP_WIDE:
            if pos + 1 < length:
                next_op = code[pos + 1]
                if next_op == OP_IINC:
                    pos += 6
                else:
                    pos += 4
            else:
                pos += 1
        elif op == OP_TABLESWITCH:
            # Align to 4-byte boundary
            pad = (4 - ((pos + 1) % 4)) % 4
            base = pos + 1 + pad
            if base + 12 <= length:
                low = struct.unpack_from('>i', code, base + 4)[0]
                high = struct.unpack_from('>i', code, base + 8)[0]
                count = high - low + 1
                if count < 0 or count > 100000:
                    break
                pos = base + 12 + count * 4
            else:
                break
        elif op == OP_LOOKUPSWITCH:
            pad = (4 - ((pos + 1) % 4)) % 4
            base = pos + 1 + pad
            if base + 8 <= length:
                npairs = struct.unpack_from('>i', code, base + 4)[0]
                if npairs < 0 or npairs > 100000:
                    break
                pos = base + 8 + npairs * 8
            else:
                break
        elif op == OP_GOTO_W or op == OP_JSR_W:
            pos += 5
        elif op in (OP_IF_ICMPEQ, OP_IF_ICMPNE, OP_IF_ICMPLT, OP_IF_ICMPGE,
                     OP_IF_ICMPGT, OP_IF_ICMPLE, OP_IF_ACMPEQ, OP_IF_ACMPNE,
                     OP_GOTO, OP_JSR, OP_IFNULL, OP_IFNONNULL,
                     OP_IFEQ, OP_IFNE, OP_IFLT, OP_IFGE, OP_IFGT, OP_IFLE):
            recent = []  # branch - reset tracking
            pos += 3
        else:
            # Single-byte opcodes (most arithmetic, stack ops, returns, etc.)
            # Some push to stack, some don't - for safety just track as other
            if op in (0x01,):  # aconst_null
                recent.append(('other', None))
            elif 0x1A <= op <= 0x35:  # iload_0..aload_3, iaload..saload
                recent.append(('other', None))
            pos += 1

        # Keep recent list bounded
        if len(recent) > 10:
            recent = recent[-5:]

    return results


def find_decrypt_classes(jar_path):
    """First pass: find classes with decrypt methods (native or indexOf-style).
    Returns: (native_class_names, indexof_class_names) — sets of class names."""
    native_decrypt = set()
    indexof_decrypt = set()

    # The indexOf bytecode signature: toCharArray, loop with bipush 0x5F, iand, ixor, key++
    INDEXOF_PATTERN = bytes([0x10, 0x5F, 0x7E, 0x82])  # bipush 95, iand, ixor

    with zipfile.ZipFile(jar_path, 'r') as zf:
        for entry in zf.namelist():
            if not entry.endswith('.class'):
                continue
            data = zf.read(entry)
            if len(data) < 10 or data[:4] != b'\xCA\xFE\xBA\xBE':
                continue
            try:
                cp = ConstantPool(data, 8)
                offset = cp.end_offset
                this_class_idx = struct.unpack_from('>H', data, offset + 2)[0]
                class_name = cp.get_class_name(this_class_idx)
                offset += 6

                # Skip interfaces
                ic = struct.unpack_from('>H', data, offset)[0]
                offset += 2 + ic * 2

                # Skip fields
                fc = struct.unpack_from('>H', data, offset)[0]
                offset += 2
                for _ in range(fc):
                    offset += 6
                    ac = struct.unpack_from('>H', data, offset)[0]
                    offset += 2
                    for _ in range(ac):
                        a_len = struct.unpack_from('>I', data, offset + 2)[0]
                        offset += 6 + a_len

                # Check methods
                mc = struct.unpack_from('>H', data, offset)[0]
                offset += 2
                for _ in range(mc):
                    m_flags = struct.unpack_from('>H', data, offset)[0]
                    m_name_idx = struct.unpack_from('>H', data, offset + 2)[0]
                    m_desc_idx = struct.unpack_from('>H', data, offset + 4)[0]
                    offset += 6
                    ac = struct.unpack_from('>H', data, offset)[0]
                    offset += 2

                    code_bytes = None
                    for _ in range(ac):
                        a_name_idx = struct.unpack_from('>H', data, offset)[0]
                        a_len = struct.unpack_from('>I', data, offset + 2)[0]
                        a_name = cp.get_utf8(a_name_idx)
                        if a_name == 'Code' and a_len >= 12:
                            code_len = struct.unpack_from('>I', data, offset + 6 + 4)[0]
                            code_bytes = data[offset + 6 + 8:offset + 6 + 8 + code_len]
                        offset += 6 + a_len

                    is_native = (m_flags & 0x0100) != 0
                    is_static = (m_flags & 0x0008) != 0
                    desc = cp.get_utf8(m_desc_idx)

                    if desc == '(Ljava/lang/String;I)Ljava/lang/String;':
                        if is_native:
                            native_decrypt.add(class_name)
                        elif is_static and code_bytes and INDEXOF_PATTERN in code_bytes:
                            indexof_decrypt.add(class_name)
            except Exception:
                pass
    return native_decrypt, indexof_decrypt


def process_jar(jar_path, output_dir=None):
    """Process all .class files in a JAR and extract decrypted strings."""
    # First pass: find the decrypt class(es)
    native_decrypt, indexof_decrypt = find_decrypt_classes(jar_path)
    if native_decrypt:
        print(f"Found {len(native_decrypt)} native XOR decrypt class(es)")
    if indexof_decrypt:
        print(f"Found {len(indexof_decrypt)} indexOf-style decrypt class(es)")
    if not native_decrypt and not indexof_decrypt:
        print("No decrypt classes found, falling back to matching all (String,int)->String calls")

    all_results = {}
    class_data = {}

    with zipfile.ZipFile(jar_path, 'r') as zf:
        for entry in zf.namelist():
            if entry.endswith('.class'):
                data = zf.read(entry)
                class_data[entry] = data
                class_name, strings = scan_class_for_decrypted_strings(
                    data,
                    native_decrypt if native_decrypt else None,
                    indexof_decrypt if indexof_decrypt else None)
                if strings:
                    all_results[entry] = (class_name, strings)

    # Print results
    total = 0
    print(f"\n{'='*80}")
    print(f"DashO XOR String Decryption Results")
    print(f"JAR: {jar_path}")
    print(f"{'='*80}\n")

    # Sort by class file path
    for entry in sorted(all_results.keys()):
        class_name, strings = all_results[entry]
        display_name = class_name or entry
        print(f"\n── {display_name} ({entry}) ──")
        for method_name, encrypted, key, decrypted, mref in strings:
            total += 1
            # Show printable version of encrypted string
            enc_repr = repr(encrypted)
            if len(enc_repr) > 60:
                enc_repr = enc_repr[:57] + "..."
            print(f"  {method_name}(): key={key}")
            print(f"    → {decrypted}")
        print()

    print(f"{'='*80}")
    print(f"Total decrypted strings: {total}")
    print(f"Classes with encrypted strings: {len(all_results)}")
    print(f"Total classes scanned: {len(class_data)}")
    print(f"{'='*80}")

    # Analyze class metadata for name suggestions
    print(f"\n{'='*80}")
    print("Class Analysis & Name Suggestions")
    print(f"{'='*80}\n")

    class_info = {}
    with zipfile.ZipFile(jar_path, 'r') as zf:
        for entry in zf.namelist():
            if not entry.endswith('.class'):
                continue
            data = zf.read(entry)
            if len(data) < 10 or data[:4] != b'\xCA\xFE\xBA\xBE':
                continue
            try:
                cp = ConstantPool(data, 8)
                offset = cp.end_offset
                access = struct.unpack_from('>H', data, offset)[0]
                this_idx = struct.unpack_from('>H', data, offset + 2)[0]
                super_idx = struct.unpack_from('>H', data, offset + 4)[0]
                this_name = cp.get_class_name(this_idx) or '?'
                super_name = cp.get_class_name(super_idx) or '?'
                offset += 6

                # Check if class name is obfuscated (contains combining marks or zero-width chars)
                is_obfuscated = any(ord(c) > 0x300 or ord(c) in (0x200B, 0x200C, 0x200D, 0x202A,
                    0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2069, 0x180E, 0x3164, 0xFFA0,
                    0x2800, 0x2060) for c in this_name)
                if not is_obfuscated:
                    continue

                # Interfaces
                ic = struct.unpack_from('>H', data, offset)[0]
                offset += 2
                interfaces = []
                for j in range(ic):
                    iface_idx = struct.unpack_from('>H', data, offset + j * 2)[0]
                    iface_name = cp.get_class_name(iface_idx)
                    if iface_name:
                        interfaces.append(iface_name)

                # Collect all referenced class names from constant pool
                refs = set()
                for e in cp.entries:
                    if e and e[0] == 'Class':
                        cn = cp.get_utf8(e[1])
                        if cn and not any(ord(c) > 0x300 for c in cn):
                            refs.add(cn)

                # Check for native methods
                has_native = b'\x01\x00' in data  # simplified check

                info = {
                    'super': super_name,
                    'interfaces': interfaces,
                    'refs': refs,
                    'access': access,
                }

                # Suggest name based on decrypted strings
                if entry in all_results:
                    _, strings = all_results[entry]
                    decrypted = [d for _, _, _, d, _ in strings]
                    info['strings'] = decrypted

                class_info[entry] = info

                # Print interesting classes
                super_short = super_name.split('/')[-1] if '/' in super_name else super_name
                iface_short = [i.split('/')[-1] for i in interfaces]

                notable_refs = [r for r in refs if r.startswith(('java/net', 'java/security',
                    'javax/crypto', 'java/lang/Runtime', 'java/lang/Process'))]

                if super_short not in ('Object', '?') or interfaces or notable_refs or entry in all_results:
                    print(f"  {entry[:60]}...")
                    if super_short not in ('Object', '?'):
                        print(f"    extends: {super_name}")
                    if interfaces:
                        print(f"    implements: {', '.join(iface_short)}")
                    if notable_refs:
                        print(f"    refs: {', '.join(notable_refs)}")
                    if entry in all_results:
                        _, strings = all_results[entry]
                        sample = [d for _, _, _, d, _ in strings][:3]
                        for s in sample:
                            clean = ''.join(c for c in s if 32 <= ord(c) < 127)[:60]
                            if clean:
                                print(f"    string: \"{clean}\"")
                    print()

            except Exception:
                pass

    # Also dump to JSON if output_dir specified
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        json_out = {
            'jar': jar_path,
            'total_classes': len(class_data),
            'decrypt_methods': {
                'native_xor': list(native_decrypt),
                'indexof_rolling_xor': list(indexof_decrypt),
            },
            'decrypted_strings': {},
            'class_analysis': {},
        }
        for entry in sorted(all_results.keys()):
            class_name, strings = all_results[entry]
            json_out['decrypted_strings'][entry] = {
                'class_name': class_name,
                'strings': [
                    {
                        'method': m,
                        'key': k,
                        'decrypted': d,
                        'decrypt_class': mref[0] if mref else None,
                        'algorithm': 'indexOf' if (indexof_decrypt and mref and mref[0] in indexof_decrypt) else 'native_xor'
                    }
                    for m, e, k, d, mref in strings
                ]
            }
        for entry, info in class_info.items():
            json_out['class_analysis'][entry] = {
                'super': info['super'],
                'interfaces': info['interfaces'],
                'notable_refs': [r for r in info.get('refs', set())
                                 if r.startswith(('java/net', 'java/security', 'javax/crypto',
                                                  'java/lang/Runtime', 'java/lang/Process'))],
            }

        json_path = os.path.join(output_dir, 'decrypted_strings.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_out, f, indent=2, ensure_ascii=False)
        print(f"\nJSON output saved to: {json_path}")

    return all_results


def deobfuscate_jar(jar_path):
    """Library API: deobfuscate a JAR and return structured results.

    Returns dict with:
        'detected': bool — whether DashO encryption was found
        'algorithms': list[str] — e.g. ['native_xor', 'indexOf_rolling_xor']
        'total_decrypted': int
        'classes_with_strings': int
        'strings': list[dict] — each has 'class', 'method', 'decrypted', 'algorithm'
    """
    try:
        if not zipfile.is_zipfile(jar_path):
            return {'detected': False, 'algorithms': [], 'total_decrypted': 0,
                    'classes_with_strings': 0, 'strings': []}

        native_decrypt, indexof_decrypt_classes = find_decrypt_classes(jar_path)
        if not native_decrypt and not indexof_decrypt_classes:
            return {'detected': False, 'algorithms': [], 'total_decrypted': 0,
                    'classes_with_strings': 0, 'strings': []}

        algorithms = []
        if native_decrypt:
            algorithms.append('native_xor')
        if indexof_decrypt_classes:
            algorithms.append('indexOf_rolling_xor')

        all_strings = []
        classes_with = 0

        with zipfile.ZipFile(jar_path, 'r') as zf:
            for entry in zf.namelist():
                if not entry.endswith('.class'):
                    continue
                data = zf.read(entry)
                class_name, strings = scan_class_for_decrypted_strings(
                    data,
                    native_decrypt if native_decrypt else None,
                    indexof_decrypt_classes if indexof_decrypt_classes else None)
                if strings:
                    classes_with += 1
                    for method_name, encrypted, key, decrypted, mref in strings:
                        algo = 'indexOf_rolling_xor' if (indexof_decrypt_classes and mref
                                and mref[0] in indexof_decrypt_classes) else 'native_xor'
                        # Clean decrypted string — strip non-printable tails
                        clean = ''.join(c for c in decrypted if 32 <= ord(c) < 127 or c in '\n\r\t')
                        if clean:
                            all_strings.append({
                                'class': class_name or entry,
                                'method': method_name,
                                'decrypted': clean,
                                'algorithm': algo,
                            })

        return {
            'detected': True,
            'algorithms': algorithms,
            'total_decrypted': len(all_strings),
            'classes_with_strings': classes_with,
            'strings': all_strings,
        }
    except (zipfile.BadZipFile, ValueError, KeyError):
        return {'detected': False, 'algorithms': [], 'total_decrypted': 0,
                'classes_with_strings': 0, 'strings': []}
    except Exception as exc:
        return {'detected': False, 'algorithms': [], 'total_decrypted': 0,
                'classes_with_strings': 0, 'strings': [],
                'error': f'{type(exc).__name__}: {exc}'}


def process_class(class_path):
    """Process a single .class file."""
    with open(class_path, 'rb') as f:
        data = f.read()
    class_name, strings = scan_class_for_decrypted_strings(data)
    if strings:
        print(f"\n── {class_name or class_path} ──")
        for method_name, encrypted, key, decrypted, mref in strings:
            print(f"  {method_name}(): key={key}")
            print(f"    → {decrypted}")
    else:
        print(f"No encrypted strings found in {class_path}")
    return strings


if __name__ == '__main__':
    import codecs
    # Fix Windows console encoding
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, errors='replace')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, errors='replace')

    import argparse
    parser = argparse.ArgumentParser(description='DashO XOR String Deobfuscator')
    parser.add_argument('input', help='JAR file or .class file to deobfuscate')
    parser.add_argument('--output', '-o', help='Output directory for JSON results')
    args = parser.parse_args()

    target = args.input
    if not os.path.exists(target):
        print(f"Error: {target} not found")
        sys.exit(1)

    if target.endswith('.jar') or target.endswith('.zip'):
        process_jar(target, args.output)
    elif target.endswith('.class'):
        process_class(target)
    else:
        # Try as JAR
        try:
            process_jar(target, args.output)
        except zipfile.BadZipFile:
            process_class(target)
