#!/usr/bin/env python3
"""
Generic String Deobfuscation Engine — tries all keyless/brute-forceable methods.

Methods attempted (30+):
  Byte-level:
  - Single-byte XOR brute force (0x01-0xFF)
  - Multi-byte XOR with repeating key (lengths 2-8, frequency analysis)
  - Position-dependent XOR (char[i] ^ i, char[i] ^ (i+1))
  - Position-dependent add/sub (char[i] +/- i)
  - Allatori-style rolling XOR (key+i, key^i patterns)
  - Caesar byte shift (addition mod 256)
  - Null-byte interleaved (UTF-16LE/BE → ASCII)
  - Nibble swap (high/low 4-bit swap)
  - Bit rotation (ROL/ROR 1-7 bits)
  - Bitwise NOT inversion
  - Zlib/gzip/deflate decompression
  - XOR with other constant pool strings as keys
  - RC4 decryption with constant pool string keys

  String-level:
  - Base64 decode (standard + URL-safe)
  - Base32 decode (RFC 4648)
  - Multi-layer Base64 (double/triple)
  - Base64 + zlib decompress
  - Custom Base64 alphabets (detected from constant pool)
  - ROT1-ROT25
  - Hex decode (continuous)
  - Delimited hex (colon-separated, \\x notation, 0x comma-separated)
  - Decimal byte array (comma-separated integers)
  - String reversal
  - Segment reversal (reverse around delimiters)
  - URL decode (%XX)
  - Unicode unescape (\\uXXXX)
  - HTML entity decode (&#NNN; and named entities)
  - Octal escape decode (\\NNN)
  - Double encoding (base64(xor), hex(base64))
  - String concatenation detection (split URLs/domains)

Usage:
    # As library (called from bot.py):
    from deobfuscate_generic import deobfuscate_jar
    result = deobfuscate_jar("malware.jar")

    # Standalone:
    python deobfuscate_generic.py malware.jar
"""

import base64
import re
import struct
import string
import zipfile
import zlib
import gzip
import os
import sys
import json
import io
import time
import html
from collections import Counter
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote

# ── Import constant pool parser from deobfuscate_dasho ──
_tools_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(_tools_dir))
try:
    from deobfuscate_dasho import (
        CONSTANT_Utf8, CONSTANT_String, CONSTANT_Integer,
        CONSTANT_Long, CONSTANT_Double, CONSTANT_Float,
    )
except ImportError:
    CONSTANT_Utf8 = 1
    CONSTANT_String = 8
    CONSTANT_Integer = 3
    CONSTANT_Long = 5
    CONSTANT_Double = 6
    CONSTANT_Float = 4


# ── Constant pool tag sizes ──
_CP_TAGS = {
    1: 'Utf8', 3: 'Integer', 4: 'Float', 5: 'Long', 6: 'Double',
    7: 'Class', 8: 'String', 9: 'Fieldref', 10: 'Methodref',
    11: 'InterfaceMethodref', 12: 'NameAndType', 15: 'MethodHandle',
    16: 'MethodType', 17: 'Dynamic', 18: 'InvokeDynamic',
    19: 'Module', 20: 'Package',
}

CONFIDENCE_THRESHOLD = 0.45
MAX_STRING_LEN = 10000
MIN_STRING_LEN = 4
GLOBAL_TIMEOUT = 60  # seconds

# Interesting keywords that boost score
_INTERESTING_PATTERNS = re.compile(
    r'(https?://|discord\.(gg|com)|webhook|token|password|passwd|api[_-]?key|'
    r'secret|\.exe|\.dll|\.jar|\.bat|\.ps1|\.sh|cmd\.exe|powershell|'
    r'appdata|roaming|programfiles|system32|temp[/\\]|'
    r'minecraft|fabric|forge|mixin|'
    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|'
    r'[a-zA-Z0-9.-]+\.(com|net|org|ru|xyz|io|shop|tk|ml|ga|cf|gq|top|icu|pw))',
    re.IGNORECASE
)

# Java boilerplate to skip
_BORING_PREFIXES = (
    'java/', 'javax/', 'sun/', 'com/sun/', 'org/xml/', 'org/w3c/',
    'org/apache/', 'org/objectweb/asm/', 'META-INF/', 'MANIFEST',
    'org/slf4j/', 'org/gradle/', 'kotlin/', 'kotlinx/', 'scala/',
    'net/minecraft/', 'com/mojang/', 'net/fabricmc/', 'net/minecraftforge/',
    'org/spongepowered/', 'cpw/mods/', 'org/lwjgl/',
)
_BORING_EXACT = frozenset({
    '<init>', '<clinit>', 'Code', 'LineNumberTable', 'StackMapTable',
    'SourceFile', 'Exceptions', 'InnerClasses', 'ConstantValue',
    'LocalVariableTable', 'LocalVariableTypeTable', 'Signature',
    'Deprecated', 'RuntimeVisibleAnnotations', 'RuntimeInvisibleAnnotations',
    'AnnotationDefault', 'BootstrapMethods', 'EnclosingMethod',
    'NestHost', 'NestMembers', 'Record', 'PermittedSubclasses',
    'this', 'super', 'null', 'true', 'false', 'void',
})

# Printable ASCII set for fast checking
_PRINTABLE = set(range(32, 127)) | {9, 10, 13}  # tab, newline, cr


def _is_boring(s: str) -> bool:
    if len(s) < MIN_STRING_LEN or len(s) > MAX_STRING_LEN:
        return True
    if s in _BORING_EXACT:
        return True
    # Java descriptors
    if s.startswith('(') and ')' in s:
        return True
    for prefix in _BORING_PREFIXES:
        if s.startswith(prefix):
            return True
    # Already clearly readable English text
    printable = sum(1 for c in s if c.isprintable()) / len(s)
    if printable > 0.95 and ' ' in s and len(s) > 20:
        return True
    return False


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b in _PRINTABLE) / len(data)


def _is_readable(s: str) -> bool:
    """Check if a string is mostly human-readable."""
    if not s or len(s) < 2:
        return False
    ratio = sum(1 for c in s if c.isprintable()) / len(s)
    return ratio >= 0.75


def score_result(decoded: str, original: str) -> float:
    """Score how likely this decoded string is meaningful (0.0-1.0)."""
    if not decoded or decoded == original:
        return 0.0
    if len(decoded) < 2:
        return 0.0

    score = 0.0

    # Printable ratio
    printable = sum(1 for c in decoded if c.isprintable()) / len(decoded)
    score += printable * 0.3

    # Contains interesting patterns
    if _INTERESTING_PATTERNS.search(decoded):
        score += 0.35

    # Has word-like structure (spaces, mixed case)
    if ' ' in decoded and len(decoded) > 10:
        score += 0.1
    if re.search(r'[a-z]', decoded) and re.search(r'[A-Z]', decoded):
        score += 0.05

    # Path-like
    if re.search(r'[/\\]\w+[/\\]\w+', decoded):
        score += 0.15

    # Penalize mostly non-printable
    if printable < 0.7:
        score *= 0.1

    # Penalize very short
    if len(decoded) < 4:
        score *= 0.3

    # Penalize if it looks like random garbage (low entropy variety but no structure)
    unique_chars = len(set(decoded))
    if unique_chars < 3 and len(decoded) > 5:
        score *= 0.2

    return min(score, 1.0)


# ═══════════════════════════════════════════════════════════════════════════
# Deobfuscation Methods
# ═══════════════════════════════════════════════════════════════════════════

def try_single_byte_xor(data: bytes) -> list:
    """Brute force single-byte XOR keys 0x01-0xFF."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    for key in range(1, 256):
        # Quick check first 16 bytes
        sample = bytes(b ^ key for b in data[:16])
        if _printable_ratio(sample) < 0.75:
            continue
        # Full decode
        decoded = bytes(b ^ key for b in data)
        if _printable_ratio(decoded) >= 0.8:
            try:
                s = decoded.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                try:
                    s = decoded.decode('latin-1')
                except Exception:
                    continue
            if _is_readable(s):
                results.append((s, f'xor_0x{key:02x}'))
    return results


def try_multibyte_xor(data: bytes) -> list:
    """Try repeating XOR keys of length 2-8 using frequency analysis."""
    results = []
    if len(data) < 8:
        return results
    for klen in range(2, min(9, len(data) // 2)):
        # For each byte position in the key, find most likely key byte
        # Assume most common plaintext byte is space (0x20) or 'e' (0x65) or null
        key = bytearray(klen)
        for i in range(klen):
            byte_at_pos = [data[j] for j in range(i, len(data), klen)]
            freq = Counter(byte_at_pos)
            most_common = freq.most_common(1)[0][0]
            # Try assuming most common decodes to space, null, or 'e'
            candidates = [most_common ^ 0x20, most_common ^ 0x00, most_common ^ 0x65]
            best_key_byte = 0
            best_printable = 0.0
            for kb in candidates:
                test = bytes(b ^ kb for b in byte_at_pos[:8])
                pr = _printable_ratio(test)
                if pr > best_printable:
                    best_printable = pr
                    best_key_byte = kb
            key[i] = best_key_byte

        # Decode with this key
        decoded = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
        if _printable_ratio(decoded) >= 0.8:
            try:
                s = decoded.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                try:
                    s = decoded.decode('latin-1')
                except Exception:
                    continue
            if _is_readable(s) and s.encode('utf-8') != data:
                key_hex = key.hex()
                results.append((s, f'xor_multi_{key_hex}'))
    return results


def try_base64_decode(s: str) -> list:
    """Standard base64 and URL-safe base64."""
    results = []
    if len(s) < 4:
        return results
    # Must look like base64
    if not re.match(r'^[A-Za-z0-9+/=\-_]{4,}$', s):
        return results
    # Standard base64
    try:
        decoded = base64.b64decode(s, validate=True)
        if _printable_ratio(decoded) >= 0.8:
            text = decoded.decode('utf-8', errors='replace')
            if _is_readable(text) and text != s:
                results.append((text, 'base64'))
    except Exception:
        pass
    # URL-safe base64
    try:
        decoded = base64.urlsafe_b64decode(s + '==')
        if _printable_ratio(decoded) >= 0.8:
            text = decoded.decode('utf-8', errors='replace')
            if _is_readable(text) and text != s and (text, 'base64') not in results:
                results.append((text, 'base64_urlsafe'))
    except Exception:
        pass
    return results


def try_rotn(s: str) -> list:
    """ROT1 through ROT25."""
    results = []
    # Only try on alpha-heavy strings
    alpha_count = sum(1 for c in s if c.isalpha())
    if alpha_count < len(s) * 0.5:
        return results
    for n in range(1, 26):
        decoded = []
        for c in s:
            if 'a' <= c <= 'z':
                decoded.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                decoded.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
            else:
                decoded.append(c)
        result = ''.join(decoded)
        if result != s and _INTERESTING_PATTERNS.search(result):
            results.append((result, f'rot{n}'))
    return results


def try_hex_decode(s: str) -> list:
    """Detect and decode hex-encoded strings."""
    results = []
    # Strip common prefixes
    cleaned = s
    if cleaned.startswith('0x') or cleaned.startswith('0X'):
        cleaned = cleaned[2:]
    # Must be even-length hex
    if len(cleaned) < 4 or len(cleaned) % 2 != 0:
        return results
    if not re.match(r'^[0-9a-fA-F]+$', cleaned):
        return results
    try:
        decoded = bytes.fromhex(cleaned)
        if _printable_ratio(decoded) >= 0.8:
            text = decoded.decode('utf-8', errors='replace')
            if _is_readable(text):
                results.append((text, 'hex'))
    except Exception:
        pass
    return results


def try_reverse(s: str) -> list:
    """Simple string reversal."""
    if len(s) < 4:
        return []
    rev = s[::-1]
    if rev != s and _INTERESTING_PATTERNS.search(rev):
        return [(rev, 'reversed')]
    return []


def try_url_decode(s: str) -> list:
    """Decode %XX URL encoding."""
    if '%' not in s:
        return []
    try:
        decoded = unquote(s)
        if decoded != s and _is_readable(decoded):
            return [(decoded, 'url_decode')]
    except Exception:
        pass
    return []


def try_unicode_unescape(s: str) -> list:
    """Decode \\uXXXX sequences."""
    if '\\u' not in s:
        return []
    try:
        decoded = s.encode('raw_unicode_escape').decode('unicode_escape')
        if decoded != s and _is_readable(decoded):
            return [(decoded, 'unicode_unescape')]
    except Exception:
        pass
    return []


def try_null_interleaved(data: bytes) -> list:
    """Strip null bytes — detects UTF-16LE encoded as raw bytes."""
    if len(data) < 4 or len(data) % 2 != 0:
        return []
    # Check if every other byte is null (UTF-16LE pattern)
    nulls_at_odd = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
    if nulls_at_odd >= len(data) // 2 * 0.8:
        # Extract even-position bytes
        decoded = bytes(data[i] for i in range(0, len(data), 2))
        if _printable_ratio(decoded) >= 0.8:
            text = decoded.decode('ascii', errors='replace')
            if _is_readable(text):
                return [(text, 'utf16le_strip')]
    # Also check nulls at even positions (UTF-16BE)
    nulls_at_even = sum(1 for i in range(0, len(data), 2) if data[i] == 0)
    if nulls_at_even >= len(data) // 2 * 0.8:
        decoded = bytes(data[i] for i in range(1, len(data), 2))
        if _printable_ratio(decoded) >= 0.8:
            text = decoded.decode('ascii', errors='replace')
            if _is_readable(text):
                return [(text, 'utf16be_strip')]
    return []


def try_caesar_bytes(data: bytes) -> list:
    """Byte-level Caesar shift (addition mod 256)."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    for shift in range(1, 256):
        # Quick check
        sample = bytes((b + shift) & 0xFF for b in data[:16])
        if _printable_ratio(sample) < 0.75:
            continue
        decoded = bytes((b + shift) & 0xFF for b in data)
        if _printable_ratio(decoded) >= 0.8:
            try:
                s = decoded.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                continue
            if _is_readable(s):
                # Don't duplicate single-byte XOR results (XOR and add overlap for some values)
                results.append((s, f'caesar_{shift}'))
    return results


def try_double_encoding(data: bytes, s: str) -> list:
    """Try base64(xor(data)), hex(base64(s)), etc."""
    results = []
    # Try: base64 decode, then single-byte XOR on result
    try:
        b64_decoded = base64.b64decode(s, validate=True)
        if len(b64_decoded) >= MIN_STRING_LEN:
            for key in range(1, 256):
                sample = bytes(b ^ key for b in b64_decoded[:12])
                if _printable_ratio(sample) < 0.8:
                    continue
                xored = bytes(b ^ key for b in b64_decoded)
                if _printable_ratio(xored) >= 0.85:
                    try:
                        text = xored.decode('utf-8', errors='strict')
                        if _is_readable(text) and text != s:
                            results.append((text, f'base64_xor_0x{key:02x}'))
                            break  # one good key is enough
                    except UnicodeDecodeError:
                        continue
    except Exception:
        pass

    # Try: hex decode, then base64 decode
    try:
        if re.match(r'^[0-9a-fA-F]+$', s) and len(s) >= 8 and len(s) % 2 == 0:
            hex_decoded = bytes.fromhex(s)
            b64_text = base64.b64decode(hex_decoded, validate=True)
            if _printable_ratio(b64_text) >= 0.8:
                text = b64_text.decode('utf-8', errors='replace')
                if _is_readable(text):
                    results.append((text, 'hex_base64'))
    except Exception:
        pass

    return results


def try_string_concat(class_strings: list) -> list:
    """Detect split strings that form URLs/domains when concatenated."""
    results = []
    if len(class_strings) < 2:
        return results

    # Look for sequences of short strings (2-15 chars) that might be URL fragments
    short_strings = [(i, s) for i, s in enumerate(class_strings)
                     if 1 <= len(s) <= 30 and s.isprintable()]

    # Try consecutive pairs/triples/quads
    for window in range(2, min(8, len(short_strings) + 1)):
        for start in range(len(short_strings) - window + 1):
            parts = [short_strings[start + j][1] for j in range(window)]
            # Only try if indices are roughly consecutive (within 5 of each other)
            indices = [short_strings[start + j][0] for j in range(window)]
            if indices[-1] - indices[0] > window + 5:
                continue
            joined = ''.join(parts)
            if len(joined) >= 8 and _INTERESTING_PATTERNS.search(joined):
                results.append((joined, f'concat_{window}parts'))

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        if r[0] not in seen:
            seen.add(r[0])
            unique.append(r)
    return unique


def try_decimal_byte_array(s: str) -> list:
    """Decode comma-separated decimal byte arrays like '104,116,116,112'."""
    results = []
    # Match patterns: "104,116,116,112" or "104, 116, 116, 112"
    if ',' not in s:
        return results
    cleaned = re.sub(r'\s+', '', s)
    parts = cleaned.split(',')
    if len(parts) < 4:
        return results
    try:
        byte_vals = [int(p) for p in parts]
        if all(0 <= b <= 255 for b in byte_vals):
            decoded = bytes(byte_vals)
            if _printable_ratio(decoded) >= 0.8:
                text = decoded.decode('utf-8', errors='replace')
                if _is_readable(text):
                    results.append((text, 'decimal_bytes'))
    except (ValueError, OverflowError):
        pass
    return results


def try_position_xor(data: bytes) -> list:
    """Position-dependent XOR: char[i] ^ i, char[i] ^ (i+1), etc."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    # char[i] ^ i
    decoded = bytes((data[i] ^ (i & 0xFF)) for i in range(len(data)))
    if _printable_ratio(decoded) >= 0.8:
        try:
            s = decoded.decode('utf-8', errors='strict')
            if _is_readable(s):
                results.append((s, 'xor_position_i'))
        except UnicodeDecodeError:
            pass
    # char[i] ^ (i + 1)
    decoded = bytes((data[i] ^ ((i + 1) & 0xFF)) for i in range(len(data)))
    if _printable_ratio(decoded) >= 0.8:
        try:
            s = decoded.decode('utf-8', errors='strict')
            if _is_readable(s):
                results.append((s, 'xor_position_i_plus1'))
        except UnicodeDecodeError:
            pass
    return results


def try_position_add_sub(data: bytes) -> list:
    """Position-dependent add/sub: char[i] - i, char[i] + i."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    # char[i] - i
    decoded = bytes((data[i] - i) & 0xFF for i in range(len(data)))
    if _printable_ratio(decoded) >= 0.8:
        try:
            s = decoded.decode('utf-8', errors='strict')
            if _is_readable(s):
                results.append((s, 'sub_position_i'))
        except UnicodeDecodeError:
            pass
    # char[i] + i
    decoded = bytes((data[i] + i) & 0xFF for i in range(len(data)))
    if _printable_ratio(decoded) >= 0.8:
        try:
            s = decoded.decode('utf-8', errors='strict')
            if _is_readable(s):
                results.append((s, 'add_position_i'))
        except UnicodeDecodeError:
            pass
    return results


def try_base32_decode(s: str) -> list:
    """Base32 decode (RFC 4648)."""
    results = []
    if len(s) < 8:
        return results
    if not re.match(r'^[A-Z2-7=]+$', s):
        return results
    try:
        decoded = base64.b32decode(s)
        if _printable_ratio(decoded) >= 0.8:
            text = decoded.decode('utf-8', errors='replace')
            if _is_readable(text) and text != s:
                results.append((text, 'base32'))
    except Exception:
        pass
    return results


def try_segment_reversal(s: str) -> list:
    """Reverse segments split by delimiters: 'moc.drocsid' -> 'discord.com'."""
    results = []
    for delim in ['.', '/', '\\', '-', '_']:
        if delim in s:
            parts = s.split(delim)
            # Reverse each segment
            rev_parts = [p[::-1] for p in parts]
            joined_parts_rev = delim.join(rev_parts)
            if _INTERESTING_PATTERNS.search(joined_parts_rev):
                results.append((joined_parts_rev, f'segment_reverse_{repr(delim)}'))
            # Reverse order of segments
            rev_order = delim.join(reversed(parts))
            if rev_order != s and _INTERESTING_PATTERNS.search(rev_order):
                results.append((rev_order, f'segment_reorder_{repr(delim)}'))
            # Both: reverse segments and their order
            both = delim.join(p[::-1] for p in reversed(parts))
            if both != s and both != joined_parts_rev and _INTERESTING_PATTERNS.search(both):
                results.append((both, f'segment_full_reverse_{repr(delim)}'))
    return results


def try_delimited_hex(s: str) -> list:
    """Decode hex with delimiters: '68:65:6c:6c:6f', '\\x68\\x65', '0x68,0x65'."""
    results = []
    # Colon-delimited hex
    if ':' in s and re.match(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){3,}$', s):
        try:
            decoded = bytes(int(h, 16) for h in s.split(':'))
            if _printable_ratio(decoded) >= 0.8:
                text = decoded.decode('utf-8', errors='replace')
                if _is_readable(text):
                    results.append((text, 'hex_colon'))
        except Exception:
            pass
    # \x notation
    if '\\x' in s:
        hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', s)
        if len(hex_bytes) >= 4:
            try:
                decoded = bytes(int(h, 16) for h in hex_bytes)
                if _printable_ratio(decoded) >= 0.8:
                    text = decoded.decode('utf-8', errors='replace')
                    if _is_readable(text):
                        results.append((text, 'hex_backslash_x'))
            except Exception:
                pass
    # 0x prefixed comma-separated
    if '0x' in s and ',' in s:
        hex_parts = re.findall(r'0x([0-9a-fA-F]{1,2})', s)
        if len(hex_parts) >= 4:
            try:
                decoded = bytes(int(h, 16) for h in hex_parts)
                if _printable_ratio(decoded) >= 0.8:
                    text = decoded.decode('utf-8', errors='replace')
                    if _is_readable(text):
                        results.append((text, 'hex_0x_csv'))
            except Exception:
                pass
    return results


def try_html_entity_decode(s: str) -> list:
    """Decode HTML entities: &#104;&#116;&#116;&#112; or &amp; etc."""
    if '&' not in s:
        return []
    try:
        decoded = html.unescape(s)
        if decoded != s and _is_readable(decoded):
            return [(decoded, 'html_entity')]
    except Exception:
        pass
    return []


def try_octal_decode(s: str) -> list:
    """Decode octal escapes: \\150\\164\\164\\160."""
    if '\\' not in s:
        return []
    octal_parts = re.findall(r'\\([0-7]{3})', s)
    if len(octal_parts) < 4:
        return []
    try:
        decoded = bytes(int(o, 8) for o in octal_parts)
        if _printable_ratio(decoded) >= 0.8:
            text = decoded.decode('utf-8', errors='replace')
            if _is_readable(text):
                return [(text, 'octal')]
    except Exception:
        pass
    return []


def try_multi_base64(s: str) -> list:
    """Double/triple base64 encoding."""
    results = []
    if len(s) < 8:
        return results
    try:
        first = base64.b64decode(s, validate=True)
        if _printable_ratio(first) >= 0.5:
            first_str = first.decode('utf-8', errors='replace')
            try:
                second = base64.b64decode(first_str, validate=True)
                if _printable_ratio(second) >= 0.8:
                    text = second.decode('utf-8', errors='replace')
                    if _is_readable(text) and text != s:
                        results.append((text, 'base64x2'))
                        # Try triple
                        try:
                            third = base64.b64decode(text, validate=True)
                            if _printable_ratio(third) >= 0.8:
                                text3 = third.decode('utf-8', errors='replace')
                                if _is_readable(text3):
                                    results.append((text3, 'base64x3'))
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception:
        pass
    return results


def try_zlib_decompress(data: bytes) -> list:
    """Try zlib/gzip decompression on raw data."""
    results = []
    if len(data) < 8:
        return results
    # zlib (raw deflate + zlib-wrapped)
    for wbits in [-15, 15, 31]:  # raw deflate, zlib, gzip
        try:
            decoded = zlib.decompress(data, wbits)
            if _printable_ratio(decoded) >= 0.7:
                text = decoded.decode('utf-8', errors='replace')
                if _is_readable(text) and len(text) >= MIN_STRING_LEN:
                    label = {-15: 'raw_deflate', 15: 'zlib', 31: 'gzip'}[wbits]
                    results.append((text[:2000], label))
                    break  # one success is enough
        except Exception:
            pass
    return results


def try_base64_zlib(s: str) -> list:
    """Base64 decode then zlib decompress."""
    results = []
    if len(s) < 8:
        return results
    try:
        raw = base64.b64decode(s, validate=True)
        for wbits in [-15, 15, 31]:
            try:
                decoded = zlib.decompress(raw, wbits)
                if _printable_ratio(decoded) >= 0.7:
                    text = decoded.decode('utf-8', errors='replace')
                    if _is_readable(text) and len(text) >= MIN_STRING_LEN:
                        results.append((text[:2000], 'base64_zlib'))
                        break
            except Exception:
                pass
    except Exception:
        pass
    return results


def try_nibble_swap(data: bytes) -> list:
    """Swap high and low nibbles of each byte."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    decoded = bytes(((b >> 4) | ((b & 0x0F) << 4)) & 0xFF for b in data)
    if _printable_ratio(decoded) >= 0.8:
        try:
            s = decoded.decode('utf-8', errors='strict')
            if _is_readable(s):
                results.append((s, 'nibble_swap'))
        except UnicodeDecodeError:
            pass
    return results


def try_bit_rotation(data: bytes) -> list:
    """Try bit rotation (ROL/ROR) by 1-7 bits."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    for rot in range(1, 8):
        # ROL
        decoded = bytes(((b << rot) | (b >> (8 - rot))) & 0xFF for b in data)
        if _printable_ratio(decoded) >= 0.8:
            try:
                s = decoded.decode('utf-8', errors='strict')
                if _is_readable(s):
                    results.append((s, f'rol_{rot}'))
            except UnicodeDecodeError:
                pass
        # ROR
        decoded = bytes(((b >> rot) | (b << (8 - rot))) & 0xFF for b in data)
        if _printable_ratio(decoded) >= 0.8:
            try:
                s = decoded.decode('utf-8', errors='strict')
                if _is_readable(s):
                    results.append((s, f'ror_{rot}'))
            except UnicodeDecodeError:
                pass
    return results


def try_xor_with_class_strings(data: bytes, class_strings: list) -> list:
    """Use other constant pool strings as XOR keys."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    # Try short strings (2-32 bytes) as repeating XOR keys (cap at 50 candidates)
    tried = 0
    for key_str in class_strings:
        if tried >= 50:
            break
        if len(key_str) < 2 or len(key_str) > 32:
            continue
        if key_str.startswith(('java/', 'javax/', 'org/', 'com/', 'net/')):
            continue
        try:
            key = key_str.encode('utf-8')
        except Exception:
            continue
        tried += 1
        decoded = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        if _printable_ratio(decoded) >= 0.85:
            try:
                s = decoded.decode('utf-8', errors='strict')
                if _is_readable(s) and s != key_str and _INTERESTING_PATTERNS.search(s):
                    results.append((s, f'xor_key_{key_str[:20]}'))
            except UnicodeDecodeError:
                pass
    return results


def try_custom_base64_alphabet(s: str, class_strings: list) -> list:
    """Detect custom base64 alphabets from constant pool (64-char strings)."""
    results = []
    if len(s) < 8:
        return results
    for candidate in class_strings:
        if len(candidate) == 64 and len(set(candidate)) == 64:
            # This looks like a custom base64 alphabet
            std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            try:
                # Translate from custom to standard
                trans = str.maketrans(candidate, std_alphabet)
                normalized = s.translate(trans)
                # Add padding
                pad = (4 - len(normalized) % 4) % 4
                normalized += '=' * pad
                decoded = base64.b64decode(normalized, validate=True)
                if _printable_ratio(decoded) >= 0.8:
                    text = decoded.decode('utf-8', errors='replace')
                    if _is_readable(text) and text != s:
                        results.append((text, f'custom_base64_{candidate[:8]}...'))
            except Exception:
                pass
    return results


def try_rc4_with_class_keys(data: bytes, class_strings: list) -> list:
    """Try RC4 decryption using other constant pool strings as keys."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    tried = 0
    for key_str in class_strings:
        if tried >= 30:
            break
        if len(key_str) < 2 or len(key_str) > 64:
            continue
        if key_str.startswith(('java/', 'javax/', 'org/', 'com/', 'net/', '(')):
            continue
        try:
            key = key_str.encode('utf-8')
        except Exception:
            continue
        tried += 1
        # RC4 KSA
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        # RC4 PRGA
        i = j = 0
        decoded = bytearray(len(data))
        for k in range(len(data)):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            decoded[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF]
        if _printable_ratio(bytes(decoded)) >= 0.85:
            try:
                s = decoded.decode('utf-8', errors='strict')
                if _is_readable(s) and s != key_str and _INTERESTING_PATTERNS.search(s):
                    results.append((s, f'rc4_key_{key_str[:20]}'))
            except UnicodeDecodeError:
                pass
    return results


def try_allatori_xor(data: bytes) -> list:
    """Allatori-style rolling XOR: key ^ (i+constant) patterns."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    found = False
    for key in range(1, 256):
        if found:
            break
        # Allatori style: byte ^ (key + i)
        decoded = bytes((data[i] ^ ((key + i) & 0xFF)) for i in range(len(data)))
        if _printable_ratio(decoded) >= 0.85:
            try:
                s = decoded.decode('utf-8', errors='strict')
                if _is_readable(s) and _INTERESTING_PATTERNS.search(s):
                    results.append((s, f'allatori_xor_0x{key:02x}'))
                    found = True
                    continue
            except UnicodeDecodeError:
                pass
        # Variant: byte ^ (key ^ i)
        decoded = bytes((data[i] ^ (key ^ (i & 0xFF))) for i in range(len(data)))
        if _printable_ratio(decoded) >= 0.85:
            try:
                s = decoded.decode('utf-8', errors='strict')
                if _is_readable(s) and _INTERESTING_PATTERNS.search(s):
                    results.append((s, f'allatori_xor2_0x{key:02x}'))
                    found = True
            except UnicodeDecodeError:
                pass
    return results


def try_not_invert(data: bytes) -> list:
    """Bitwise NOT (~byte & 0xFF)."""
    results = []
    if len(data) < MIN_STRING_LEN:
        return results
    decoded = bytes((~b) & 0xFF for b in data)
    if _printable_ratio(decoded) >= 0.8:
        try:
            s = decoded.decode('utf-8', errors='strict')
            if _is_readable(s):
                results.append((s, 'bitwise_not'))
        except UnicodeDecodeError:
            pass
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Constant Pool Parser (lightweight, self-contained)
# ═══════════════════════════════════════════════════════════════════════════

def parse_constant_pool(data: bytes):
    """Parse a .class file and extract constant pool entries.
    Returns (class_name: str, utf8_entries: list[tuple[int, str, bytes]])
    where each tuple is (index, string_value, raw_bytes).
    """
    if len(data) < 10:
        return None, []
    magic = struct.unpack('>I', data[:4])[0]
    if magic != 0xCAFEBABE:
        return None, []

    cp_count = struct.unpack('>H', data[8:10])[0]
    entries = [None] * cp_count  # 1-indexed
    utf8_entries = []
    pos = 10
    i = 1

    try:
        while i < cp_count and pos < len(data):
            tag = data[pos]
            pos += 1
            if tag == 1:  # Utf8
                length = struct.unpack('>H', data[pos:pos + 2])[0]
                pos += 2
                raw = data[pos:pos + length]
                pos += length
                try:
                    s = raw.decode('utf-8', errors='replace')
                except Exception:
                    s = raw.decode('latin-1', errors='replace')
                entries[i] = ('Utf8', s, raw)
                utf8_entries.append((i, s, raw))
            elif tag in (3, 4):  # Integer, Float
                pos += 4
                entries[i] = (tag,)
            elif tag in (5, 6):  # Long, Double (take 2 slots)
                pos += 8
                entries[i] = (tag,)
                i += 1  # skip next slot
            elif tag == 7:  # Class
                idx = struct.unpack('>H', data[pos:pos + 2])[0]
                pos += 2
                entries[i] = ('Class', idx)
            elif tag == 8:  # String
                idx = struct.unpack('>H', data[pos:pos + 2])[0]
                pos += 2
                entries[i] = ('String', idx)
            elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
                pos += 4
                entries[i] = (tag,)
            elif tag == 12:  # NameAndType
                pos += 4
                entries[i] = (tag,)
            elif tag == 15:  # MethodHandle
                pos += 3
                entries[i] = (tag,)
            elif tag == 16:  # MethodType
                pos += 2
                entries[i] = (tag,)
            elif tag in (17, 18):  # Dynamic, InvokeDynamic
                pos += 4
                entries[i] = (tag,)
            elif tag in (19, 20):  # Module, Package
                pos += 2
                entries[i] = (tag,)
            else:
                break  # unknown tag, bail
            i += 1
    except (struct.error, IndexError):
        pass

    # Find class name
    class_name = None
    try:
        # this_class is at pos after constant pool
        # Read access_flags(2) + this_class(2)
        # But we need to know where CP ends... just try to find it from entries
        # Actually the class index is right after the CP
        after_cp = pos
        if after_cp + 4 <= len(data):
            this_class_idx = struct.unpack('>H', data[after_cp + 2:after_cp + 4])[0]
            if 0 < this_class_idx < cp_count and entries[this_class_idx]:
                name_idx = entries[this_class_idx][1] if entries[this_class_idx][0] == 'Class' else 0
                if 0 < name_idx < cp_count and entries[name_idx] and entries[name_idx][0] == 'Utf8':
                    class_name = entries[name_idx][1]
    except Exception:
        pass

    return class_name, utf8_entries


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

def process_class(class_name: str, data: bytes) -> list:
    """Run all deobfuscation methods on one class file's constant pool."""
    parsed_name, utf8_entries = parse_constant_pool(data)
    if not utf8_entries:
        return []

    display_name = parsed_name or class_name
    results = []
    all_strings = [s for _, s, _ in utf8_entries]

    for idx, s, raw in utf8_entries:
        if _is_boring(s):
            continue

        candidates = []

        # Byte-level methods
        if len(raw) >= MIN_STRING_LEN:
            candidates += try_single_byte_xor(raw)
            if len(raw) >= 8:
                candidates += try_multibyte_xor(raw)
            candidates += try_null_interleaved(raw)
            candidates += try_position_xor(raw)
            candidates += try_position_add_sub(raw)
            candidates += try_nibble_swap(raw)
            candidates += try_not_invert(raw)
            candidates += try_zlib_decompress(raw)
            # Bit rotation and Caesar only if nothing good yet
            if not candidates:
                candidates += try_bit_rotation(raw)
                candidates += try_caesar_bytes(raw)
            # Allatori-style rolling XOR (only if nothing found — slow)
            if not candidates:
                candidates += try_allatori_xor(raw)

        # String-level methods
        candidates += try_base64_decode(s)
        candidates += try_base32_decode(s)
        candidates += try_hex_decode(s)
        candidates += try_delimited_hex(s)
        candidates += try_rotn(s)
        candidates += try_reverse(s)
        candidates += try_segment_reversal(s)
        candidates += try_url_decode(s)
        candidates += try_unicode_unescape(s)
        candidates += try_html_entity_decode(s)
        candidates += try_octal_decode(s)
        candidates += try_decimal_byte_array(s)
        candidates += try_multi_base64(s)
        candidates += try_base64_zlib(s)
        candidates += try_double_encoding(raw, s)

        for decoded, algo in candidates:
            sc = score_result(decoded, s)
            if sc >= CONFIDENCE_THRESHOLD:
                results.append({
                    'class': display_name,
                    'method': '',
                    'decrypted': decoded[:2000],  # cap length
                    'algorithm': algo,
                    'original': s[:200],
                    'score': round(sc, 3),
                })

    # String concatenation across all strings in this class
    concat_results = try_string_concat(all_strings)
    for decoded, algo in concat_results:
        sc = score_result(decoded, '')
        if sc >= CONFIDENCE_THRESHOLD:
            results.append({
                'class': display_name,
                'method': '',
                'decrypted': decoded[:2000],
                'algorithm': algo,
                'original': '[concatenated]',
                'score': round(sc, 3),
            })

    # Inter-string methods (use other strings as keys — slower, run last)
    non_boring = [(idx, s, raw) for idx, s, raw in utf8_entries
                  if not _is_boring(s) and len(raw) >= MIN_STRING_LEN]
    if len(non_boring) <= 200:  # only on manageable class sizes
        for idx, s, raw in non_boring:
            candidates = []
            candidates += try_xor_with_class_strings(raw, all_strings)
            candidates += try_custom_base64_alphabet(s, all_strings)
            # RC4 only for strings that look encrypted (low printable ratio)
            if _printable_ratio(raw) < 0.5:
                candidates += try_rc4_with_class_keys(raw, all_strings)
            for decoded, algo in candidates:
                sc = score_result(decoded, s)
                if sc >= CONFIDENCE_THRESHOLD:
                    results.append({
                        'class': display_name,
                        'method': '',
                        'decrypted': decoded[:2000],
                        'algorithm': algo,
                        'original': s[:200],
                        'score': round(sc, 3),
                    })

    return results


def deobfuscate_jar(jar_path: str) -> dict:
    """Main entry point. Scan all .class files and try every deobfuscation method.

    Returns dict matching deobfuscate_dasho schema:
        'detected': bool
        'algorithms': list[str]
        'total_decrypted': int
        'classes_with_strings': int
        'strings': list[dict]
    """
    start_time = time.time()
    try:
        if not zipfile.is_zipfile(jar_path):
            return _empty_result()

        all_results = []
        classes_with = 0

        # Pre-read all class bytes (ZipFile is not thread-safe)
        class_data = {}
        with zipfile.ZipFile(jar_path, 'r') as zf:
            for entry in zf.namelist():
                if entry.endswith('.class'):
                    try:
                        class_data[entry] = zf.read(entry)
                    except Exception:
                        pass

        # Process classes with thread pool for speed
        def _process_entry(entry_data):
            entry, data = entry_data
            if time.time() - start_time > GLOBAL_TIMEOUT:
                return entry, []
            try:
                return entry, process_class(entry, data)
            except Exception:
                return entry, []

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(_process_entry, item): item[0]
                       for item in class_data.items()}
            for future in as_completed(futures):
                if time.time() - start_time > GLOBAL_TIMEOUT:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break
                try:
                    entry, results = future.result(timeout=10)
                    if results:
                        classes_with += 1
                        all_results.extend(results)
                except Exception:
                    pass

        if not all_results:
            return _empty_result()

        # Deduplicate by (class, decrypted)
        seen = set()
        unique = []
        for r in all_results:
            key = (r['class'], r['decrypted'])
            if key not in seen:
                seen.add(key)
                unique.append(r)

        # Sort by score descending
        unique.sort(key=lambda x: x.get('score', 0), reverse=True)

        # Cap at 500 results to avoid flooding
        unique = unique[:500]

        algorithms = sorted(set(r['algorithm'] for r in unique))

        return {
            'detected': True,
            'algorithms': algorithms,
            'total_decrypted': len(unique),
            'classes_with_strings': classes_with,
            'strings': unique,
        }

    except (zipfile.BadZipFile, ValueError, KeyError):
        return _empty_result()
    except Exception as exc:
        return {**_empty_result(), 'error': f'{type(exc).__name__}: {exc}'}


def _empty_result():
    return {
        'detected': False,
        'algorithms': [],
        'total_decrypted': 0,
        'classes_with_strings': 0,
        'strings': [],
    }


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import codecs
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, errors='replace')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, errors='replace')

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <jar_file> [--json]")
        sys.exit(1)

    target = sys.argv[1]
    use_json = '--json' in sys.argv

    if not os.path.exists(target):
        print(f"Error: {target} not found")
        sys.exit(1)

    result = deobfuscate_jar(target)

    if use_json:
        print(json.dumps(result, indent=2))
    else:
        if result['detected']:
            print(f"\nFound {result['total_decrypted']} deobfuscated string(s) "
                  f"in {result['classes_with_strings']} class(es)")
            print(f"Algorithms: {', '.join(result['algorithms'])}")
            print()
            for s in result['strings']:
                print(f"  [{s['algorithm']}] {s['class']}")
                print(f"    Original: {s['original'][:80]}")
                print(f"    Decoded:  {s['decrypted'][:120]}")
                print(f"    Score:    {s.get('score', '?')}")
                print()
        else:
            print("No obfuscated strings detected.")
            if result.get('error'):
                print(f"Error: {result['error']}")
