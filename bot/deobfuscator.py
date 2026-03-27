#!/usr/bin/env python3
"""
Universal Java Deobfuscator v4.0 — works on decompiled source (.java/.txt)

Multi-layer deobfuscation pipeline that:
1. Fingerprints which obfuscator(s) were used (20+ obfuscators)
2. Runs obfuscator-specific passes
3. Runs generic passes that work on any obfuscation
4. Assesses confidence and triggers bytecode-level fallbacks if needed

Supported obfuscators (fingerprinting + specific passes):
  - Bozar        (ZWC naming, opaque predicates, junk code, CFF, XOR constants)
  - ZKM          (Zelix KlassMaster: flow obfuscation, string encryption, name mangling)
  - Allatori     (string encryption, flow obfuscation, watermarking, Cyrillic names)
  - Stringer     (string encryption via invokedynamic/reflection)
  - Skidfuscator (exception-based flow, opaque predicates)
  - Caesium      (Bozar-variant, similar patterns)
  - Radon        (flow, string, number obfuscation)
  - Smoke        (string/flow/name obfuscation)
  - DashO        (XOR string encryption, name obfuscation)
  - ProGuard/R8  (name shrinking, minimal obfuscation)
  - Paramorphism (decompiler crashers, ZIP corruption)
  - qProtect     (AES strings, MBA numerics, CFF)
  - Binscure     (invokedynamic abuse, Recaf crashers)
  - sb27         (Superblaubeere27: invokedynamic method replacement)
  - dProtect     (MBA expressions, ProGuard-based)
  - JNIC/native  (native method stubs, code in .dll/.so)
  - Scuti        (ClassLoader/defineClass packing)
  - Branchlock   (encrypted constant pool)

Generic layers (always run):
  - Dead code elimination (junk API, unreachable, bogus loops, math opaques)
  - String deobfuscation (XOR, Base64, char[], byte[], StringBuilder, stack strings)
  - URLDecoder / Unicode escape resolution
  - Bitwise NOT byte array resolution
  - Control flow simplification (opaque predicates, CFF, try-catch, synchronized junk)
  - MBA expression simplification (mixed boolean-arithmetic identities)
  - Constant folding (bitwise shifts, Integer/Long.reverse, char arithmetic, ternary)
  - Import cleanup (unused/junk imports)
  - Reflection annotation + malware flagging (exec, ProcessBuilder)
  - Cyrillic homoglyph normalization
  - Extended ZWC stripping (19 invisible Unicode characters)
  - JNIC/native detection and annotation
  - Decompiler error recovery annotation
  - Wrapper method detection

Designed for single-class deobfuscation without the full JAR.
"""

import re
import sys
import os
import argparse
import subprocess
import shutil
import base64
import struct
import urllib.parse
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════
#  OBFUSCATOR FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════

def fingerprint_obfuscator(text: str) -> dict[str, float]:
    """Detect which obfuscator(s) were likely used on the source.

    Returns dict of {obfuscator_name: confidence} where confidence is 0.0-1.0.
    Multiple obfuscators can be detected (layered obfuscation).
    """
    scores = {}

    # --- BOZAR ---
    bozar = 0.0
    if '\u200e' in text or '\\u200e' in text:
        bozar += 0.35  # ZWC naming is Bozar's signature
    if re.search(r'aO\.\w+\([^)]*null,\s*null\)', text):
        bozar += 0.30  # Opaque predicate class pattern
    if any(p in text for p in ['Statx.', 'FT_Palette_Data.', 'TT_VertHeader.', 'IOURingSQE.']):
        bozar += 0.25  # LWJGL/FreeType junk injection
    if 'BOZAR' in text:
        bozar += 0.10
    scores['bozar'] = min(bozar, 1.0)

    # --- ZKM (Zelix KlassMaster) ---
    zkm = 0.0
    # ZKM uses try-catch flow obfuscation with specific exception patterns
    if text.count('catch (') > 20 and text.count('throw ') > 10:
        zkm += 0.20
    # ZKM string encryption: static initializer with char arrays + XOR
    if re.search(r'static\s+\{[^}]*new\s+char\[', text, re.DOTALL):
        zkm += 0.15
    # ZKM naming: 'a', 'b', 'c' single-letter methods + II/Il/lI field names
    if len(re.findall(r'\b[IlO]{2,6}\b', text)) > 20:
        zkm += 0.30  # Il, II, lI, OO naming pattern
    # ZKM flow: switch inside while(true) with throw in default
    if re.search(r'while\s*\(true\)\s*\{[^}]*switch[^}]*throw\s+null', text, re.DOTALL):
        zkm += 0.25
    # ZKM enhanced flow: PopularEmptyInstruction pattern
    if 'SYNTHETIC' in text and 'BRIDGE' in text:
        zkm += 0.10
    scores['zkm'] = min(zkm, 1.0)

    # --- ALLATORI ---
    allatori = 0.0
    # Allatori uses specific string decryption: static method with charAt ^ key
    if re.search(r'ALLATORIxDEMO', text, re.IGNORECASE):
        allatori += 0.90  # Dead giveaway demo watermark
    # Allatori naming: Unicode chars like \u0435\u0440 (Cyrillic lookalikes)
    cyrillic_count = len(re.findall(r'[\u0400-\u04FF]', text))
    if cyrillic_count > 10:
        allatori += 0.30
    # Allatori string decryption: method with charAt and XOR loop
    if re.search(r'\.charAt\(\w+\)\s*\^\s*\w+', text):
        allatori += 0.15
    # Allatori flow: ternary abuse (nested ? : chains)
    ternary_count = text.count(' ? ')
    if ternary_count > 30:
        allatori += 0.15
    # Allatori watermark in annotations
    if re.search(r'@\w*Allatori', text, re.IGNORECASE):
        allatori += 0.50
    scores['allatori'] = min(allatori, 1.0)

    # --- STRINGER ---
    stringer = 0.0
    # Stringer uses invokedynamic for string encryption
    if text.count('invokedynamic') > 5 or text.count('makeConcatWithConstants') > 10:
        stringer += 0.15
    # Stringer class pattern: hidden class with decrypt method
    if re.search(r'private\s+static\s+String\s+\w{1,3}\(String\s+\w+\)', text):
        stringer += 0.15
    # Stringer: DecryptionAgent / Stringer markers
    if 'stringer' in text.lower() or 'DecryptionAgent' in text:
        stringer += 0.50
    # Stringer: heavily encoded string constants (long hex-like strings)
    long_strings = re.findall(r'"[^"]{100,}"', text)
    if len(long_strings) > 5:
        stringer += 0.20
    scores['stringer'] = min(stringer, 1.0)

    # --- SKIDFUSCATOR ---
    skidfuscator = 0.0
    # Skidfuscator uses exception-based control flow
    if text.count('try {') > 20 and text.count('catch (Throwable') > 5:
        skidfuscator += 0.25
    # Skidfuscator opaque predicates using exception handlers
    if re.search(r'catch\s*\(\w+Exception\s+\w+\)\s*\{[^}]*continue', text):
        skidfuscator += 0.25
    # Skidfuscator naming: number-only method names
    if len(re.findall(r'private\s+static\s+\w+\s+\d+\(', text)) > 3:
        skidfuscator += 0.30
    # Skidfuscator switch-based flow with computed hashes
    if re.search(r'switch\s*\(\w+\.hashCode\(\)\)', text):
        skidfuscator += 0.20
    scores['skidfuscator'] = min(skidfuscator, 1.0)

    # --- CAESIUM (Bozar variant) ---
    caesium = 0.0
    # Caesium shares many Bozar traits but has different markers
    if 'Caesium' in text or 'caesium' in text:
        caesium += 0.60
    # Caesium uses similar ZWC but with different opaque predicate class
    if bozar > 0.3 and not re.search(r'aO\.\w+\(', text):
        caesium += 0.20  # ZWC but no aO class = might be Caesium
    scores['caesium'] = min(caesium, 1.0)

    # --- RADON ---
    radon = 0.0
    # Radon string encryption: String(new byte[]{...})
    if len(re.findall(r'new\s+String\s*\(\s*new\s+byte\s*\[', text)) > 3:
        radon += 0.30
    # Radon flow: labeled blocks with break
    if len(re.findall(r'\w+:\s*\{', text)) > 5:
        radon += 0.15
    # Radon number obfuscation: Integer.parseInt("decimal")
    if len(re.findall(r'Integer\.parseInt\("', text)) > 3:
        radon += 0.25
    # Radon: Long.parseLong for constants
    if len(re.findall(r'Long\.parseLong\("', text)) > 3:
        radon += 0.20
    scores['radon'] = min(radon, 1.0)

    # --- SMOKE ---
    smoke = 0.0
    # Smoke uses String.toCharArray() + manipulation
    if len(re.findall(r'\.toCharArray\(\)', text)) > 10:
        smoke += 0.15
    # Smoke string encryption: specific decrypt pattern
    if re.search(r'new\s+String\s*\(\s*\w+\s*,\s*\d+\s*,\s*\d+\s*\)', text):
        smoke += 0.20
    # Smoke flow: switch(0) { default: ... }
    if 'switch (0)' in text or 'switch(0)' in text:
        smoke += 0.30
    scores['smoke'] = min(smoke, 1.0)

    # --- DASHO ---
    dasho = 0.0
    # DashO string encryption: static method(String, int) pattern
    if re.search(r'static\s+String\s+\w\(String\s+\w+,\s*int\s+\w+\)', text):
        dasho += 0.30
    # DashO naming: single-letter class/method names with 'a' prefix
    if len(re.findall(r'\b[a-e]\.\w\(', text)) > 20:
        dasho += 0.20
    # DashO: PreEmptive markers
    if 'PreEmptive' in text or 'DashO' in text:
        dasho += 0.50
    scores['dasho'] = min(dasho, 1.0)

    # --- PROGUARD / R8 ---
    proguard = 0.0
    # ProGuard naming: sequential a, b, c, ..., aa, ab naming
    single_letter_methods = len(re.findall(r'\b[a-z]{1,2}\(', text))
    if single_letter_methods > 50:
        proguard += 0.20
    # ProGuard keeps structure but renames — fewer obfuscation artifacts
    if proguard > 0 and not any(scores.get(k, 0) > 0.3 for k in scores if k != 'proguard'):
        proguard += 0.20  # If only naming is obfuscated, likely ProGuard
    scores['proguard'] = min(proguard, 1.0)

    # --- PARAMORPHISM ---
    paramorphism = 0.0
    if text.count('// INTERNAL ERROR //') > 3:
        paramorphism += 0.30
    if 'Underrun type stack' in text:
        paramorphism += 0.40
    if text.count('/* Error */') > 5:
        paramorphism += 0.25
    # Nearly empty class files — only native methods
    native_count = len(re.findall(r'\bnative\s+\w+\s+\w+\(', text))
    if native_count > 10 and text.count('public ') < 5:
        paramorphism += 0.20
    scores['paramorphism'] = min(paramorphism, 1.0)

    # --- qPROTECT ---
    qprotect = 0.0
    if re.search(r'Cipher\.getInstance\(\s*"AES', text):
        qprotect += 0.15
    # MBA-style arithmetic (deeply nested bitwise)
    if len(re.findall(r'\(\([^)]+\)\s*[\^&|]\s*\([^)]+\)\)', text)) > 10:
        qprotect += 0.20
    # CFF: multiple while(true) switch patterns
    cff_count = len(re.findall(r'while\s*\(true\)\s*\{', text))
    if cff_count > 2:
        qprotect += 0.15
    if 'qProtect' in text or 'qprotect' in text:
        qprotect += 0.50
    scores['qprotect'] = min(qprotect, 1.0)

    # --- BINSCURE ---
    binscure = 0.0
    if text.count('invokedynamic') > 20:
        binscure += 0.25
    if text.count('try {') > 30 and text.count('invokedynamic') > 10:
        binscure += 0.20
    error_methods = len(re.findall(r'/\*\s*(?:Error|Unable to|INTERNAL)\s*\*/', text))
    if error_methods > 5:
        binscure += 0.20
    if 'binscure' in text.lower() or 'binclub' in text.lower():
        binscure += 0.50
    scores['binscure'] = min(binscure, 1.0)

    # --- SUPERBLAUBEERE27 (sb27) ---
    sb27 = 0.0
    if text.count('invokedynamic') > 5:
        sb27 += 0.10
    if re.search(r'private\s+static\s+String\s+\w+\(\s*int\s+\w+\s*,\s*int\s+\w+\s*\)', text):
        sb27 += 0.20
    if re.search(r'for\s*\(\s*;;\s*\)\s*\{[^}]*switch', text, re.DOTALL):
        sb27 += 0.15
    scores['sb27'] = min(sb27, 1.0)

    # --- dPROTECT ---
    dprotect = 0.0
    # MBA: (x ^ y) + 2 * (x & y) = x + y
    if re.search(r'\(\w+\s*\^\s*\w+\)\s*\+\s*2\s*\*\s*\(\w+\s*&\s*\w+\)', text):
        dprotect += 0.30
    # MBA: (a & b) + (a | b) = a + b
    if re.search(r'\(\w+\s*&\s*\w+\)\s*\+\s*\(\w+\s*\|\s*\w+\)', text):
        dprotect += 0.25
    # Double negation patterns
    if len(re.findall(r'~\w+\s*[\^&|]\s*~?\w+', text)) > 5:
        dprotect += 0.15
    scores['dprotect'] = min(dprotect, 1.0)

    # --- JNIC / NATIVE-OBFUSCATOR ---
    native_obf = 0.0
    method_count = len(re.findall(r'(?:public|private|protected|static)\s+\w+\s+\w+\(', text))
    if method_count > 0 and native_count / max(method_count, 1) > 0.5:
        native_obf += 0.40
    if 'System.loadLibrary' in text or 'System.load(' in text:
        native_obf += 0.20
    if re.search(r'public\s+native\s+\w+\s+\w+\([^)]*\);', text):
        native_obf += 0.20
    if 'jnic' in text.lower() or 'JNIC' in text:
        native_obf += 0.40
    scores['jnic'] = min(native_obf, 1.0)

    # --- SCUTI ---
    scuti = 0.0
    if 'ClassLoader' in text and 'defineClass' in text:
        scuti += 0.20
    if re.search(r'new\s+String\s*\(\s*new\s+byte\[\]\s*\{[^}]+\}\s*\)\s*\.replace', text):
        scuti += 0.20
    if 'Pack200' in text or 'scuti' in text.lower():
        scuti += 0.30
    scores['scuti'] = min(scuti, 1.0)

    # --- BRANCHLOCK ---
    branchlock = 0.0
    if len(re.findall(r'"[\x80-\xff]{10,}"', text)) > 5:
        branchlock += 0.20
    if len(re.findall(r'\w{1,3}\.\w{1,3}\(\s*\d+\s*\)', text)) > 20:
        branchlock += 0.15
    if 'branchlock' in text.lower():
        branchlock += 0.50
    scores['branchlock'] = min(branchlock, 1.0)

    # --- NEONOBF ---
    neonobf = 0.0
    if 'NeonObf' in text or 'neonobf' in text:
        neonobf += 0.60
    if re.search(r'static\s+String\s+\w+\(String\s+\w+,\s*int\s+\w+\)', text):
        neonobf += 0.15
    if re.search(r'if\s*\(\w+\.\w+\)\s*\{', text) and text.count('return;') > 10:
        neonobf += 0.10
    scores['neonobf'] = min(neonobf, 1.0)

    # --- UNIOBFUSCATOR ---
    uniobf = 0.0
    unicode_escapes = len(re.findall(r'\\u[0-9a-fA-F]{4}', text))
    if unicode_escapes > 50:
        uniobf += 0.30
    if unicode_escapes > 200:
        uniobf += 0.30
    if 'UniObfuscator' in text:
        uniobf += 0.50
    scores['uniobfuscator'] = min(uniobf, 1.0)

    # --- JOBFUSCATOR (PELock) ---
    jobf = 0.0
    # Source-level obfuscation: Unicode escapes + dead code + string splits
    if unicode_escapes > 20 and text.count('new StringBuilder') > 10:
        jobf += 0.20
    if 'JObfuscator' in text or 'PELock' in text:
        jobf += 0.50
    scores['jobfuscator'] = min(jobf, 1.0)

    # --- SKIDSUITE2 / HSGUARD ---
    skidsuite = 0.0
    if 'SkidSuite' in text or 'skidsuite' in text:
        skidsuite += 0.50
    if 'HsGuard' in text or 'hsguard' in text:
        skidsuite += 0.50
    # Generic "skid" obfuscator traits: simple flow + string encryption
    if text.count('try {') > 10 and re.search(r'static\s+String\s+\w\(', text):
        skidsuite += 0.10
    scores['skidsuite'] = min(skidsuite, 1.0)

    # --- GENERIC / UNKNOWN ---
    # Check for signs of obfuscation that don't match any known tool
    generic_signs = 0.0
    # Excessive string concatenation (split strings)
    if text.count('new StringBuilder') > 20 or text.count('StringBuffer') > 20:
        generic_signs += 0.15
    # Reflection-based method calls
    if text.count('Class.forName') > 3 or text.count('.getDeclaredMethod') > 3:
        generic_signs += 0.20
    # Encoded string arrays
    if re.search(r'new\s+String\[\]\s*\{[^}]*"[A-Za-z0-9+/=]{20,}"', text):
        generic_signs += 0.25
    if generic_signs > 0 and not any(v > 0.4 for v in scores.values()):
        scores['unknown'] = min(generic_signs, 1.0)

    # Filter to only detected obfuscators (confidence > 0.15)
    return {k: v for k, v in scores.items() if v > 0.15}


# ═══════════════════════════════════════════════════════════════════════
#  GENERIC DEOBFUSCATION LAYERS (work on any obfuscator)
# ═══════════════════════════════════════════════════════════════════════

def generic_string_deobfuscation(text: str) -> tuple[str, int]:
    """Decode common string obfuscation patterns found in decompiled source.

    Handles:
    - Base64 encoded strings: new String(Base64.decode("..."))
    - Char array construction: new String(new char[]{'a','b','c'})
    - XOR decryption inline: (char)(str.charAt(i) ^ key)
    - Integer.parseInt / Long.parseLong for number hiding
    - String(byte[]) construction
    - StringBuilder concatenation collapse
    """
    count = 0

    # --- Base64 strings ---
    def decode_b64_match(m):
        nonlocal count
        try:
            decoded = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
            if decoded.isprintable() and len(decoded) > 2:
                count += 1
                return f'"{decoded}"  /* [DEOBF] Base64 decoded */'
        except Exception:
            pass
        return m.group(0)

    # Base64.getDecoder().decode("...") or Base64.decode("...")
    text = re.sub(
        r'Base64\.(?:getDecoder\(\)\.)?decode[^\(]*\(\s*"([A-Za-z0-9+/=]{4,})"\s*\)',
        decode_b64_match, text
    )

    # new String(Base64...) patterns
    text = re.sub(
        r'new\s+String\s*\(\s*Base64\.(?:getDecoder\(\)\.)?decode\s*\(\s*"([A-Za-z0-9+/=]{4,})"\s*\)\s*\)',
        decode_b64_match, text
    )

    # --- Integer.parseInt / Long.parseLong ---
    def resolve_parse_int(m):
        nonlocal count
        try:
            val = int(m.group(1))
            count += 1
            return f'{val}  /* [DEOBF] parseInt resolved */'
        except ValueError:
            return m.group(0)

    text = re.sub(r'Integer\.parseInt\(\s*"(-?\d+)"\s*\)', resolve_parse_int, text)
    text = re.sub(r'Long\.parseLong\(\s*"(-?\d+)"\s*\)', resolve_parse_int, text)

    # --- Char array to string ---
    def collapse_char_array(m):
        nonlocal count
        chars_raw = m.group(1)
        chars = re.findall(r"'(\\u[0-9a-fA-F]{4}|\\.|.)'", chars_raw)
        if chars and len(chars) >= 2:
            decoded = []
            for c in chars:
                if c.startswith('\\u') and len(c) == 6:
                    decoded.append(chr(int(c[2:], 16)))
                elif c == '\\n':
                    decoded.append('\n')
                elif c == '\\t':
                    decoded.append('\t')
                elif c == '\\r':
                    decoded.append('\r')
                elif c == '\\\\':
                    decoded.append('\\')
                elif c == "\\'":
                    decoded.append("'")
                elif c.startswith('\\') and len(c) == 2:
                    decoded.append(c[1])
                else:
                    decoded.append(c)
            result = ''.join(decoded)
            if result.isprintable():
                count += 1
                return f'"{result}"  /* [DEOBF] char[] collapsed */'
        return m.group(0)

    text = re.sub(
        r'new\s+String\s*\(\s*new\s+char\s*\[\s*\]\s*\{([^}]+)\}\s*\)',
        collapse_char_array, text
    )

    # --- String(byte[]{...}) ---
    def collapse_byte_array(m):
        nonlocal count
        try:
            bytes_raw = m.group(1)
            byte_vals = [int(x.strip()) & 0xFF for x in re.findall(r'-?\d+', bytes_raw)]
            decoded = bytes(byte_vals).decode('utf-8', errors='replace')
            if decoded.isprintable() and len(decoded) >= 2:
                count += 1
                return f'"{decoded}"  /* [DEOBF] byte[] decoded */'
        except Exception:
            pass
        return m.group(0)

    text = re.sub(
        r'new\s+String\s*\(\s*new\s+byte\s*\[\s*\]\s*\{([^}]+)\}\s*\)',
        collapse_byte_array, text
    )

    # --- StringBuilder collapse ---
    # Pattern: new StringBuilder("a").append("b").append("c").toString()
    def collapse_stringbuilder(m):
        nonlocal count
        full = m.group(0)
        parts = re.findall(r'"([^"]*)"', full)
        if len(parts) >= 2:
            result = ''.join(parts)
            count += 1
            return f'"{result}"  /* [DEOBF] StringBuilder collapsed */'
        return full

    text = re.sub(
        r'new\s+StringBuilder\s*\(\s*"[^"]*"\s*\)(?:\s*\.append\s*\(\s*"[^"]*"\s*\))+\s*\.toString\s*\(\s*\)',
        collapse_stringbuilder, text
    )

    return text, count


def generic_reflection_cleanup(text: str) -> tuple[str, int]:
    """Annotate and simplify reflection-based method calls.

    Patterns:
    - Class.forName("com.example.Foo").getMethod("bar", ...)
    - Method.invoke(obj, args)
    """
    count = 0

    # Annotate Class.forName with the class name
    def annotate_forname(m):
        nonlocal count
        count += 1
        return m.group(0) + f'  /* [DEOBF] Loads: {m.group(1)} */'

    text = re.sub(
        r'Class\.forName\(\s*"([^"]+)"\s*\)',
        annotate_forname, text
    )

    # Annotate getMethod/getDeclaredMethod with method name
    def annotate_getmethod(m):
        nonlocal count
        count += 1
        return m.group(0) + f'  /* [DEOBF] Method: {m.group(1)} */'

    text = re.sub(
        r'\.(?:get|getDeclared)Method\(\s*"([^"]+)"',
        annotate_getmethod, text
    )

    # Annotate getField/getDeclaredField
    text = re.sub(
        r'\.(?:get|getDeclared)Field\(\s*"([^"]+)"',
        lambda m: m.group(0) + f'  /* [DEOBF] Field: {m.group(1)} */',
        text
    )

    return text, count


def generic_try_catch_cleanup(text: str) -> tuple[str, int]:
    """Remove empty or junk try-catch blocks used for flow obfuscation.

    Common patterns:
    - try { real_code } catch (Exception e) { } (empty catch)
    - try { code; throw null; } catch (NullPointerException e) { real_code } (exception flow)
    """
    lines = text.split('\n')
    result = []
    removed = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        # Pattern: catch (...) { } — empty catch block
        if re.match(r'}\s*catch\s*\([^)]+\)\s*\{\s*}', stripped):
            indent = len(lines[i]) - len(lines[i].lstrip())
            result.append(' ' * indent + '// [DEOBF] Empty catch block removed')
            removed += 1
            i += 1
            continue

        # Pattern: catch (...) { single junk statement }
        if re.match(r'}\s*catch\s*\([^)]+\)\s*\{', stripped):
            # Check if the catch body is just 1-2 lines
            j = i + 1
            body_lines = []
            while j < len(lines) and lines[j].strip() != '}':
                if lines[j].strip():
                    body_lines.append(lines[j].strip())
                j += 1
            if len(body_lines) == 0:
                # Empty catch
                indent = len(lines[i]) - len(lines[i].lstrip())
                result.append(' ' * indent + '// [DEOBF] Empty catch block removed')
                removed += 1
                i = j + 1
                continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), removed


def generic_number_deobfuscation(text: str) -> tuple[str, int]:
    """Simplify obfuscated number patterns beyond XOR.

    Handles:
    - (A | B) & (~A | C) → bitwise tricks
    - Double.longBitsToDouble(CONST) → actual double
    - Float.intBitsToFloat(CONST) → actual float
    - Long.reverse/reverseBytes patterns
    """
    count = 0

    # Float.intBitsToFloat(known_int) → float value
    def resolve_float(m):
        nonlocal count
        try:
            val = int(m.group(1))
            f = struct.unpack('f', struct.pack('I', val & 0xFFFFFFFF))[0]
            count += 1
            return f'{f:.6g}f  /* [DEOBF] Float resolved */'
        except Exception:
            return m.group(0)

    text = re.sub(r'Float\.intBitsToFloat\(\s*(-?\d+)\s*\)', resolve_float, text)

    # Double.longBitsToDouble(known_long) → double value
    def resolve_double(m):
        nonlocal count
        try:
            val = int(m.group(1))
            d = struct.unpack('d', struct.pack('Q', val & 0xFFFFFFFFFFFFFFFF))[0]
            count += 1
            return f'{d:.6g}  /* [DEOBF] Double resolved */'
        except Exception:
            return m.group(0)

    text = re.sub(r'Double\.longBitsToDouble\(\s*(-?\d+)[Ll]?\s*\)', resolve_double, text)

    return text, count


def generic_dead_code_elimination(text: str) -> tuple[str, int]:
    """Remove generic dead code patterns that aren't obfuscator-specific.

    - if (false) { ... }
    - if (true) { ... } else { ... } → keep only if-body
    - while (false) { ... }
    - Unreachable code after return/throw/break/continue
    """
    lines = text.split('\n')
    result = []
    removed = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        # if (false) { ... } → remove entirely
        if re.match(r'if\s*\(\s*false\s*\)\s*\{', stripped):
            block_end = _find_block_end(lines, i)
            if block_end > i:
                indent = len(lines[i]) - len(lines[i].lstrip())
                result.append(' ' * indent + '// [DEOBF] Dead code (if false) removed')
                removed += 1
                i = block_end + 1
                continue

        # while (false) { ... } → remove entirely
        if re.match(r'while\s*\(\s*false\s*\)\s*\{', stripped):
            block_end = _find_block_end(lines, i)
            if block_end > i:
                indent = len(lines[i]) - len(lines[i].lstrip())
                result.append(' ' * indent + '// [DEOBF] Dead code (while false) removed')
                removed += 1
                i = block_end + 1
                continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), removed


# ═══════════════════════════════════════════════════════════════════════
#  EXTENDED GENERIC PASSES (v4.0)
# ═══════════════════════════════════════════════════════════════════════

# --- Full ZWC character set ---
ZWC_ALL = [
    '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
    '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
    '\uFEFF', '\u00AD', '\u034F', '\u061C',
    '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
]
ZWC_ALL_ESCAPED = ['\\u%04x' % ord(c) for c in ZWC_ALL]

# --- Cyrillic homoglyph map ---
CYRILLIC_TO_LATIN = {
    '\u0430': 'a', '\u0435': 'e', '\u0456': 'i', '\u043E': 'o',
    '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
    '\u04BB': 'h', '\u0410': 'A', '\u0412': 'B', '\u0415': 'E',
    '\u041A': 'K', '\u041C': 'M', '\u041D': 'H', '\u041E': 'O',
    '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
}


def extended_zwc_strip(text: str) -> tuple[str, int]:
    """Strip ALL zero-width and invisible Unicode characters, not just \\u200e."""
    count = 0
    for c in ZWC_ALL:
        n = text.count(c)
        if n:
            text = text.replace(c, '')
            count += n
    for esc in ZWC_ALL_ESCAPED:
        n = text.count(esc)
        if n:
            text = text.replace(esc, '')
            count += n
    return text, count


def cyrillic_homoglyph_cleanup(text: str) -> tuple[str, int]:
    """Replace Cyrillic lookalike characters with their Latin equivalents."""
    count = 0
    for cyrillic, latin in CYRILLIC_TO_LATIN.items():
        n = text.count(cyrillic)
        if n:
            text = text.replace(cyrillic, latin)
            count += n
    return text, count


def mba_simplify(text: str) -> tuple[str, int]:
    """Simplify Mixed Boolean-Arithmetic (MBA) expressions.

    Handles dProtect, qProtect, and custom MBA patterns:
      (x ^ y) + 2 * (x & y)  ->  x + y
      (x & y) + (x | y)      ->  x + y
      (~x & y) | (x & ~y)    ->  x ^ y
      (x & ~y) | (~x & y)    ->  x ^ y
      ~(~x)                   ->  x
      -(-(x))                 ->  x
    """
    count = 0

    # (x ^ y) + 2 * (x & y) -> x + y
    pat = r'\((\w+)\s*\^\s*(\w+)\)\s*\+\s*2\s*\*\s*\(\1\s*&\s*\2\)'
    text, n = re.subn(pat, r'\1 + \2  /* [DEOBF] MBA simplified */', text)
    count += n

    # 2 * (x & y) + (x ^ y) -> x + y (reordered)
    pat = r'2\s*\*\s*\((\w+)\s*&\s*(\w+)\)\s*\+\s*\(\1\s*\^\s*\2\)'
    text, n = re.subn(pat, r'\1 + \2  /* [DEOBF] MBA simplified */', text)
    count += n

    # (x & y) + (x | y) -> x + y
    pat = r'\((\w+)\s*&\s*(\w+)\)\s*\+\s*\(\1\s*\|\s*\2\)'
    text, n = re.subn(pat, r'\1 + \2  /* [DEOBF] MBA simplified */', text)
    count += n

    # (~x & y) | (x & ~y) -> x ^ y
    pat = r'\(~(\w+)\s*&\s*(\w+)\)\s*\|\s*\(\1\s*&\s*~\2\)'
    text, n = re.subn(pat, r'\1 ^ \2  /* [DEOBF] MBA simplified */', text)
    count += n

    # (x & ~y) | (~x & y) -> x ^ y (reversed)
    pat = r'\((\w+)\s*&\s*~(\w+)\)\s*\|\s*\(~\1\s*&\s*\2\)'
    text, n = re.subn(pat, r'\1 ^ \2  /* [DEOBF] MBA simplified */', text)
    count += n

    # ~(~x) -> x
    text, n = re.subn(r'~\(~(\w+)\)', r'\1', text)
    count += n

    # -(-(x)) -> x
    text, n = re.subn(r'-\(-(\w+)\)', r'\1', text)
    count += n

    return text, count


def math_opaque_predicate_elimination(text: str) -> tuple[str, int]:
    """Eliminate mathematical and known-true/false opaque predicates.

    Always true:
      (x*x + x) % 2 == 0         (for all integers)
      x*(x+1) % 2 == 0            (consecutive ints, one is even)
      "str" != null                (string literals are never null)
      null == null                 (identity)
      "".isEmpty()                 (empty string is always empty)
      "".length() == 0             (same)
      System.nanoTime() % 1 == 0   (anything mod 1 is 0)
      (int)Math.PI == 3            (always true)
      (int)Math.E == 2             (always true)
      Thread.currentThread()!=null (thread is never null)
      x instanceof Object          (everything is an Object)
    """
    count = 0

    # First pass: replace known always-true expressions inline
    always_true_patterns = [
        (r'System\.nanoTime\(\)\s*%\s*1\s*==\s*0', 'true'),
        (r'""\s*\.length\(\)\s*==\s*0', 'true'),
        (r'""\s*\.isEmpty\(\)', 'true'),
        (r'null\s*==\s*null', 'true'),
        (r'\(int\)\s*\(?\s*Math\.PI\s*\)?\s*==\s*3', 'true'),
        (r'\(int\)\s*\(?\s*Math\.E\s*\)?\s*==\s*2', 'true'),
        (r'Thread\.currentThread\(\)\s*!=\s*null', 'true'),
        (r'\w+\s+instanceof\s+Object', 'true'),
    ]
    for pattern, replacement in always_true_patterns:
        text, n = re.subn(pattern, replacement + '  /* [DEOBF] opaque predicate */', text)
        count += n

    # Second pass: structural elimination of if-blocks with known-true conditions
    lines = text.split('\n')
    result = []
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()
        replaced = False

        # (x*x + x) % 2 == 0 -> always true
        if re.search(r'if\s*\(\s*\(\w+\s*\*\s*\w+\s*\+\s*\w+\)\s*%\s*2\s*==\s*0\s*\)', stripped):
            indent = len(lines[i]) - len(lines[i].lstrip())
            result.append(' ' * indent + '// [DEOBF] Opaque predicate (always true) - math identity')
            block_end = _find_block_end(lines, i)
            if block_end > i:
                start_body = i + 1
                if start_body < block_end and lines[start_body].strip() == '{':
                    start_body += 1
                for j in range(start_body, block_end):
                    result.append(lines[j])
                i = block_end + 1
                count += 1
                replaced = True

        # x * (x + 1) % 2 == 0 -> always true
        if not replaced and re.search(r'if\s*\(\s*\w+\s*\*\s*\(\s*\w+\s*\+\s*1\s*\)\s*%\s*2\s*==\s*0', stripped):
            indent = len(lines[i]) - len(lines[i].lstrip())
            result.append(' ' * indent + '// [DEOBF] Opaque predicate (always true) - n*(n+1) is even')
            block_end = _find_block_end(lines, i)
            if block_end > i:
                start_body = i + 1
                if start_body < block_end and lines[start_body].strip() == '{':
                    start_body += 1
                for j in range(start_body, block_end):
                    result.append(lines[j])
                i = block_end + 1
                count += 1
                replaced = True

        # "string_literal" != null -> always true
        if not replaced and re.search(r'if\s*\(\s*"[^"]*"\s*!=\s*null\s*\)', stripped):
            indent = len(lines[i]) - len(lines[i].lstrip())
            result.append(' ' * indent + '// [DEOBF] Opaque predicate ("str" != null is always true)')
            block_end = _find_block_end(lines, i)
            if block_end > i:
                start_body = i + 1
                if start_body < block_end and lines[start_body].strip() == '{':
                    start_body += 1
                for j in range(start_body, block_end):
                    result.append(lines[j])
                i = block_end + 1
                count += 1
                replaced = True

        if not replaced:
            result.append(lines[i])
            i += 1

    return '\n'.join(result), count


def try_finally_unwrap(text: str) -> tuple[str, int]:
    """Unwrap try {} finally { body } blocks where try is empty (Allatori pattern)."""
    count = 0
    # Simple regex for single-depth
    text, n = re.subn(
        r'try\s*\{\s*\}\s*finally\s*\{',
        '{ // [DEOBF] Empty try-finally unwrapped',
        text)
    count += n
    return text, count


def bogus_loop_removal(text: str) -> tuple[str, int]:
    """Remove loops that execute exactly once.

    Patterns:
      for(int i=0; i<1; i++) { body }  -> body
      do { body } while(false);         -> body
    """
    count = 0

    # for(int i=0; i<1; i++) { ... }
    def replace_single_for(m):
        nonlocal count
        count += 1
        return '/* [DEOBF] Bogus for-loop removed */ {'
    text = re.sub(
        r'for\s*\(\s*int\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*1\s*;\s*\w+\+\+\s*\)\s*\{',
        replace_single_for, text)

    # do { ... } while(false); — only remove while(false) closings, don't touch do{
    text, n = re.subn(r'\}\s*while\s*\(\s*false\s*\)\s*;',
                       '} // [DEOBF] do-while(false) unwrapped', text)
    count += n

    return text, count


def stack_string_reconstruction(text: str) -> tuple[str, int]:
    """Reconstruct strings built char-by-char into arrays.

    Pattern: char[] c = new char[N]; c[0]='h'; c[1]='e'; ... -> "hello"
    """
    count = 0

    # Find char array declarations
    decl_pattern = re.compile(r'char\[\]\s+(\w+)\s*=\s*new\s+char\[\s*(\d+)\s*\]\s*;')
    assign_pattern_template = r'{name}\[\s*(\d+)\s*\]\s*=\s*\'(.)\'\s*;'

    for m in decl_pattern.finditer(text):
        var_name = m.group(1)
        size = int(m.group(2))
        if size > 200:
            continue

        # Scope search to region near the declaration (max 500 chars per array slot)
        search_start = m.start()
        search_end = min(len(text), m.end() + size * 500)
        search_region = text[search_start:search_end]

        assign_re = re.compile(assign_pattern_template.format(name=re.escape(var_name)))
        chars = {}
        for am in assign_re.finditer(search_region):
            idx = int(am.group(1))
            ch = am.group(2)
            if idx < size:
                chars[idx] = ch

        if len(chars) >= size * 0.7 and size >= 3:
            reconstructed = ''.join(chars.get(i, '?') for i in range(size))
            # Add annotation after the declaration
            annotation = f'  // [DEOBF] Stack string: "{reconstructed}"'
            text = text.replace(m.group(0), m.group(0) + annotation, 1)
            count += 1

    return text, count


def url_decoder_resolution(text: str) -> tuple[str, int]:
    """Resolve URLDecoder.decode() calls with literal string arguments."""
    count = 0

    def resolve_url(m):
        nonlocal count
        try:
            decoded = urllib.parse.unquote(m.group(1))
            if decoded.isprintable() and len(decoded) > 1:
                count += 1
                return f'"{decoded}"  /* [DEOBF] URLDecoder resolved */'
        except Exception:
            pass
        return m.group(0)

    text = re.sub(
        r'URLDecoder\.decode\(\s*"([^"]+)"\s*,\s*"[^"]+"\s*\)',
        resolve_url, text)

    return text, count


def bitwise_not_byte_resolution(text: str) -> tuple[str, int]:
    """Resolve ~(-N) patterns in byte arrays to actual byte values.

    Pattern: new byte[]{~(-105), ~(-102)} -> new byte[]{104, 101} -> "he"
    """
    count = 0

    def resolve_byte_array_nots(m):
        nonlocal count
        inner = m.group(1)
        def resolve_single(nm):
            nonlocal count
            val = int(nm.group(1))
            result = ~val & 0xFF
            count += 1
            return str(result)
        resolved = re.sub(r'~\(\s*(-?\d+)\s*\)', resolve_single, inner)
        return f'new byte[]{{{resolved}}}'

    # Only resolve ~(-N) inside byte array initializers
    text = re.sub(
        r'new\s+byte\s*\[\s*\]\s*\{([^}]*~\([^}]*)\}',
        resolve_byte_array_nots, text
    )

    return text, count


def integer_reverse_resolution(text: str) -> tuple[str, int]:
    """Resolve Integer.reverse(), Integer.reverseBytes(), and Long equivalents."""
    count = 0

    def resolve_int_reverse(m):
        nonlocal count
        val = int(m.group(1)) & 0xFFFFFFFF
        result = int('{:032b}'.format(val)[::-1], 2)
        count += 1
        return str(result)

    def resolve_int_reverse_bytes(m):
        nonlocal count
        val = int(m.group(1)) & 0xFFFFFFFF
        result = struct.unpack('>I', struct.pack('<I', val))[0]
        count += 1
        return str(result)

    def resolve_long_reverse(m):
        nonlocal count
        val = int(m.group(1)) & 0xFFFFFFFFFFFFFFFF
        result = int('{:064b}'.format(val)[::-1], 2)
        count += 1
        return f'{result}L'

    def resolve_long_reverse_bytes(m):
        nonlocal count
        val = int(m.group(1)) & 0xFFFFFFFFFFFFFFFF
        result = struct.unpack('>Q', struct.pack('<Q', val))[0]
        count += 1
        return f'{result}L'

    text = re.sub(r'Integer\.reverse\(\s*(-?\d+)\s*\)', resolve_int_reverse, text)
    text = re.sub(r'Integer\.reverseBytes\(\s*(-?\d+)\s*\)', resolve_int_reverse_bytes, text)
    text = re.sub(r'Long\.reverse\(\s*(-?\d+)L?\s*\)', resolve_long_reverse, text)
    text = re.sub(r'Long\.reverseBytes\(\s*(-?\d+)L?\s*\)', resolve_long_reverse_bytes, text)

    return text, count


def char_arithmetic_resolution(text: str) -> tuple[str, int]:
    """Resolve character arithmetic: (char)('A' + 1) -> 'B', (int)'A' -> 65."""
    count = 0

    def resolve_char_add(m):
        nonlocal count
        ch = m.group(1)
        offset = int(m.group(2))
        code_point = ord(ch) + offset
        if 0 <= code_point <= 0x10FFFF and not (0xD800 <= code_point <= 0xDFFF):
            result = chr(code_point)
            if result.isprintable():
                count += 1
                return f"'{result}'"
        return m.group(0)

    def resolve_char_sub(m):
        nonlocal count
        ch = m.group(1)
        offset = int(m.group(2))
        code_point = ord(ch) - offset
        if 0 <= code_point <= 0x10FFFF and not (0xD800 <= code_point <= 0xDFFF):
            result = chr(code_point)
            if result.isprintable():
                count += 1
                return f"'{result}'"
        return m.group(0)

    def resolve_int_cast(m):
        nonlocal count
        ch = m.group(1)
        count += 1
        return str(ord(ch))

    text = re.sub(r"\(char\)\(\s*'(.)'\s*\+\s*(\d+)\s*\)", resolve_char_add, text)
    text = re.sub(r"\(char\)\(\s*'(.)'\s*-\s*(\d+)\s*\)", resolve_char_sub, text)
    text = re.sub(r"\(int\)\s*'(.)'", resolve_int_cast, text)

    return text, count


def bitwise_shift_resolution(text: str) -> tuple[str, int]:
    """Resolve constant bitwise shift expressions: (1 << 5) | (1 << 3) -> 40."""
    count = 0

    # Simple: (1 << N) -> value
    def resolve_shift(m):
        nonlocal count
        base = int(m.group(1))
        shift = int(m.group(2))
        if 0 <= shift <= 63:
            count += 1
            return str(base << shift)
        return m.group(0)

    text = re.sub(r'\(\s*(\d+)\s*<<\s*(\d+)\s*\)', resolve_shift, text)

    return text, count


def ternary_constant_resolution(text: str) -> tuple[str, int]:
    """Resolve ternary expressions with constant conditions: true ? x : y -> x."""
    count = 0
    text, n = re.subn(r'\btrue\s*\?\s*([^:]+?)\s*:\s*[^;,)]+', r'\1  /* [DEOBF] ternary resolved */', text)
    count += n
    text, n = re.subn(r'\bfalse\s*\?\s*[^:]+?\s*:\s*([^;,)]+)', r'\1  /* [DEOBF] ternary resolved */', text)
    count += n
    return text, count


def synchronized_junk_removal(text: str) -> tuple[str, int]:
    """Remove synchronized(new Object()) { ... } junk wrappers."""
    count = 0
    lines = text.split('\n')
    result = []
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()
        if re.match(r'synchronized\s*\(\s*new\s+Object\(\)\s*\)\s*\{', stripped):
            block_end = _find_block_end(lines, i)
            if block_end > i:
                indent = len(lines[i]) - len(lines[i].lstrip())
                result.append(' ' * indent + '// [DEOBF] Junk synchronized(new Object()) removed')
                for j in range(i + 1, block_end):
                    result.append(lines[j])
                count += 1
                i = block_end + 1
                continue
        result.append(lines[i])
        i += 1

    return '\n'.join(result), count


def enhanced_reflection_annotation(text: str) -> tuple[str, int]:
    """Annotate reflection chains and flag dangerous calls."""
    count = 0

    # Runtime.getRuntime().exec(...) -> [MALWARE] Command execution
    def annotate_exec(m):
        nonlocal count
        count += 1
        return m.group(0) + '  /* [MALWARE] Command execution */'
    text = re.sub(
        r'Runtime\.getRuntime\(\)\.exec\(\s*([^)]+)\s*\)',
        annotate_exec, text)

    # ProcessBuilder
    def annotate_pb(m):
        nonlocal count
        count += 1
        return m.group(0) + '  /* [MALWARE] Process creation */'
    text = re.sub(
        r'new\s+ProcessBuilder\(',
        annotate_pb, text)

    # Class.forName().getDeclaredField().get()
    def annotate_field_access(m):
        nonlocal count
        count += 1
        cls = m.group(1)
        field = m.group(2)
        return m.group(0) + f'  /* [DEOBF] Reads field: {cls}.{field} */'
    text = re.sub(
        r'Class\.forName\("([^"]+)"\)\.getDeclaredField\("([^"]+)"\)\.get\(\w+\)',
        annotate_field_access, text)

    # Class.forName().getConstructor().newInstance()
    def annotate_new_instance(m):
        nonlocal count
        count += 1
        cls = m.group(1)
        return m.group(0) + f'  /* [DEOBF] Creates new: {cls} */'
    text = re.sub(
        r'Class\.forName\("([^"]+)"\)\.getConstructor\([^)]*\)\.newInstance\(',
        annotate_new_instance, text)

    return text, count


def jnic_detection_annotation(text: str) -> tuple[str, int]:
    """Detect and annotate JNIC/native-obfuscated code."""
    count = 0
    native_methods = re.findall(r'(public|private|protected)\s+native\s+\w+\s+(\w+)\(', text)
    if len(native_methods) > 5:
        # Add header annotation
        header = ('// [DEOBF] WARNING: This class uses native method obfuscation (JNIC/native-obfuscator)\n'
                  '// Method bodies are compiled to native code in a .dll/.so file\n'
                  '// Java-level deobfuscation cannot recover the original logic\n'
                  f'// {len(native_methods)} native methods detected\n')
        # Find class declaration and insert after it
        class_match = re.search(r'((?:public|private)?\s*class\s+\w+[^{]*\{)', text)
        if class_match:
            text = text[:class_match.end()] + '\n' + header + text[class_match.end():]
            count = len(native_methods)
    return text, count


def unicode_escape_resolution(text: str) -> tuple[str, int]:
    """Resolve Java Unicode escape sequences in identifiers and strings.

    Pattern: \\u0041\\u0042 -> AB
    """
    count = 0

    def resolve_unicode(m):
        nonlocal count
        try:
            ch = chr(int(m.group(1), 16))
            if ch.isprintable() and ord(ch) > 31:
                count += 1
                return ch
        except (ValueError, OverflowError):
            pass
        return m.group(0)

    text = re.sub(r'\\u([0-9a-fA-F]{4})', resolve_unicode, text)

    return text, count


def windows_reserved_name_detection(text: str) -> tuple[str, int]:
    """Detect Windows reserved names used as obfuscation (Allatori, Caesium)."""
    count = 0
    reserved = ['AUX', 'CON', 'PRN', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
                'LPT1', 'LPT2', 'LPT3', 'CLOCK$']
    for name in reserved:
        # Match as class/method/field name (standalone word)
        pattern = rf'\b{re.escape(name)}\b'
        matches = re.findall(pattern, text)
        if len(matches) > 2:  # More than 2 uses = likely obfuscation
            count += len(matches)
    if count > 0:
        header = f'// [DEOBF] WARNING: {count} Windows reserved names detected (obfuscation indicator)\n'
        text = header + text
    return text, count


def il_confusable_annotation(text: str) -> tuple[str, int]:
    """Detect and annotate Il/lI confusable naming patterns (ZKM)."""
    count = 0
    # Find all Il/lI style identifiers
    # Only match identifiers with at least two different confusable chars (not just "111" or "OOO")
    raw = set(re.findall(r'\b([IlO1]{3,})\b', text))
    confusables = {s for s in raw if len(set(s) & {'I', 'l'}) >= 1 and len(set(s)) >= 2}
    if len(confusables) > 5:
        # Many confusable names = ZKM-style obfuscation
        count = len(confusables)
        header = (f'// [DEOBF] WARNING: {count} confusable Il/lI identifiers detected (ZKM-style naming)\n'
                  '// These names use mixtures of I (uppercase i) and l (lowercase L) that look identical\n')
        text = header + text
    return text, count


def aes_string_annotation(text: str) -> tuple[str, int]:
    """Detect and annotate AES/DES/RC4 cipher-based string encryption."""
    count = 0

    # AES/DES pattern: Cipher.getInstance + SecretKeySpec
    if re.search(r'Cipher\.getInstance\(\s*"(AES|DES|DESede)', text):
        # Find the decrypt method containing cipher usage
        methods = re.findall(
            r'((?:private|static|public)\s+static\s+String\s+\w+\([^)]*\)\s*\{[^}]*Cipher\.getInstance[^}]*\})',
            text, re.DOTALL)
        for m in methods:
            count += 1
        # Try to extract hardcoded key
        key_match = re.search(r'new\s+SecretKeySpec\(\s*"([^"]+)"\.getBytes\(', text)
        if key_match:
            key = key_match.group(1)
            text = text.replace(key_match.group(0),
                                key_match.group(0) + f'  /* [DEOBF] AES key: "{key}" */')
            count += 1

    # RC4 pattern: byte[256] S-box
    if re.search(r'new\s+byte\[256\]', text) and re.search(r'for\s*\([^)]*256[^)]*\)', text):
        count += 1
        text = re.sub(r'(new\s+byte\[256\])',
                       r'\1  /* [DEOBF] RC4 S-box detected */', text, count=1)

    return text, count


def string_table_resolution(text: str) -> tuple[str, int]:
    """Detect string tables (static String[] with index access) and annotate."""
    count = 0

    # Find static String[] declarations with initializers
    table_pattern = re.compile(
        r'(?:private|static|public)\s+static\s+(?:final\s+)?String\[\]\s+(\w+)\s*=\s*'
        r'(?:new\s+String\[\]\s*)?\{([^}]+)\}',
        re.DOTALL)

    for m in table_pattern.finditer(text):
        var_name = m.group(1)
        values_str = m.group(2)
        # Extract string values
        values = re.findall(r'"([^"]*)"', values_str)
        if len(values) >= 3:
            # Find accesses like TABLE[N]
            access_pattern = re.compile(rf'{re.escape(var_name)}\[(\d+)\]')
            insertions = []
            for am in access_pattern.finditer(text):
                idx = int(am.group(1))
                if idx < len(values):
                    annotation = f'  /* [DEOBF] = "{values[idx]}" */'
                    pos = am.end()
                    if pos < len(text) and '/* [DEOBF]' not in text[pos:pos+20]:
                        insertions.append((pos, annotation))
            # Apply in reverse to preserve positions
            for pos, annotation in reversed(insertions):
                text = text[:pos] + annotation + text[pos:]
                count += 1

    return text, count


def decompiler_error_annotation(text: str) -> tuple[str, int]:
    """Detect and annotate decompiler failures (Paramorphism, Binscure, etc.)."""
    count = 0
    error_patterns = [
        (r'//\s*INTERNAL ERROR\s*//', 'Decompiler internal error'),
        (r'/\*\s*Error\s*\*/', 'Decompilation failure'),
        (r'Underrun type stack', 'Bytecode corruption (Paramorphism?)'),
        (r'// Unable to fully structure code', 'Partial decompilation'),
        (r'\*\* GOTO', 'Irreducible control flow'),
    ]
    for pattern, label in error_patterns:
        matches = re.findall(pattern, text)
        if matches:
            count += len(matches)
    if count > 0:
        lines = text.split('\n')
        header = (f'// [DEOBF] WARNING: {count} decompiler errors detected\n'
                  '// This class may use anti-decompilation techniques (Paramorphism, Binscure, etc.)\n'
                  '// Some method bodies may be missing or garbled\n')
        # Insert at top of file
        text = header + text
    return text, count


# ═══════════════════════════════════════════════════════════════════════
#  ZKM-SPECIFIC DEOBFUSCATION
# ═══════════════════════════════════════════════════════════════════════

def zkm_flow_deobfuscation(text: str) -> tuple[str, int]:
    """Remove ZKM's try-catch flow obfuscation and switch dispatch patterns."""
    lines = text.split('\n')
    result = []
    removed = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        # ZKM pattern: while(true) { switch(var) { ... throw null in default } }
        if re.match(r'\s*while\s*\(true\)\s*\{', stripped):
            block_end = _find_block_end(lines, i)
            if block_end and block_end > i:
                block_text = '\n'.join(lines[i:block_end + 1])
                if 'throw null' in block_text and 'switch' in block_text:
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    result.append(' ' * indent + '// [DEOBF] ZKM flow dispatch removed')
                    removed += 1
                    i = block_end + 1
                    continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), removed


# ═══════════════════════════════════════════════════════════════════════
#  ALLATORI-SPECIFIC DEOBFUSCATION
# ═══════════════════════════════════════════════════════════════════════

def allatori_string_deobfuscation(text: str) -> tuple[str, int]:
    """Decode Allatori's charAt XOR string encryption pattern.

    Allatori pattern: method that takes a String, XORs each charAt with a
    rolling key, returns decrypted string.
    """
    count = 0

    # Annotate Allatori decrypt calls
    # Pattern: ClassName.a("encrypted_string") or a("encrypted_string")
    # where 'a' is typically the decrypt method
    if 'ALLATORIxDEMO' in text:
        text = text.replace('ALLATORIxDEMO', '/* [DEOBF] Allatori watermark */')
        count += 1

    return text, count


# ═══════════════════════════════════════════════════════════════════════
#  SKIDFUSCATOR-SPECIFIC DEOBFUSCATION
# ═══════════════════════════════════════════════════════════════════════

def skidfuscator_exception_flow_cleanup(text: str) -> tuple[str, int]:
    """Remove Skidfuscator's exception-based control flow obfuscation.

    Skidfuscator uses intentional exceptions as control flow:
    - try { value = 1/0; } catch (ArithmeticException) { real_code; }
    - try { ((String)null).length(); } catch (NPE) { real_code; }
    """
    lines = text.split('\n')
    result = []
    removed = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        # Pattern: try { intentional_exception; } catch (...) { real_code; }
        if stripped == 'try {' or re.match(r'try\s*\{', stripped):
            block_end = _find_block_end(lines, i)
            if block_end and block_end > i and block_end - i <= 5:
                block_text = '\n'.join(lines[i:block_end + 1])
                # Check for intentional exception triggers
                intentional = any(p in block_text for p in [
                    '1 / 0', '1/0', 'null).', 'throw new ',
                    'Integer.parseInt("a")', 'String)null',
                ])
                if intentional:
                    # Keep the catch body, remove the try
                    next_i = block_end + 1
                    if next_i < len(lines) and 'catch' in lines[next_i]:
                        catch_end = _find_block_end(lines, next_i)
                        if catch_end:
                            # Extract catch body — add annotation first, then body
                            indent = len(lines[i]) - len(lines[i].lstrip())
                            result.append(' ' * indent + '// [DEOBF] Skidfuscator exception flow simplified')
                            for j in range(next_i + 1, catch_end):
                                if lines[j].strip() and lines[j].strip() != '}':
                                    result.append(lines[j])
                            removed += 1
                            i = catch_end + 1
                            continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), removed


# ═══════════════════════════════════════════════════════════════════════
#  RADON-SPECIFIC DEOBFUSCATION
# ═══════════════════════════════════════════════════════════════════════

def radon_number_deobfuscation(text: str) -> tuple[str, int]:
    """Resolve Radon's Integer.parseInt/Long.parseLong number hiding."""
    count = 0

    def resolve_parse(m):
        nonlocal count
        try:
            val = int(m.group(2))
            count += 1
            suffix = 'L' if 'Long' in m.group(1) else ''
            return f'{val}{suffix}  /* [DEOBF] Radon number resolved */'
        except ValueError:
            return m.group(0)

    text = re.sub(r'(Integer|Long)\.parse(?:Int|Long)\(\s*"(-?\d+)"\s*\)', resolve_parse, text)
    return text, count


# ═══════════════════════════════════════════════════════════════════════
# JUNK API DATABASE — calls that ONLY appear in dead code branches.
# If a block contains any of these, it's dead code injected by Bozar.
# ═══════════════════════════════════════════════════════════════════════

JUNK_API_PATTERNS = [
    # LWJGL / native struct accessors — never used in real mod code paths
    r"Statx\.\w+\(",
    r"DEVMODE\.\w+\(",
    r"Flock\.\w+\(",
    r"IOURingSQE\.\w+\(",
    r"STBTTAlignedQuad\.\w+\(",
    r"STBTTVertex\.\w+\(",
    r"STBVorbisInfo\.\w+\(",
    r"STBVorbis\.n\w+\(",

    # FreeType native accessors
    r"FT_Palette_Data\.n\w+\(",
    r"FT_Face\.n\w+\(",
    r"FT_GlyphSlot\.n\w+\(",
    r"TT_MaxProfile\.n\w+\(",
    r"TT_Header\.n\w+\(",
    r"TT_OS2\.n\w+\(",
    r"TT_PCLT\.n\w+\(",
    r"TT_VertHeader\.n\w+\(",
    r"TT_HoriHeader\.n\w+\(",
    r"TT_Postscript\.n\w+\(",

    # JNI direct calls
    r"JNI\.invoke\w+",
    r"JNI\.call\w+",

    # ICU internals
    r"com\.ibm\.icu\.text\.UTF16\.\w+\(",
    r"jdk\.internal\.icu\.text\.UTF16\.\w+\(",
    r"UCharacter\.\w+\(",
    r"AsciiUtil\.\w+\(",

    # Guava math/primitives (used with garbage args)
    r"Chars\.checkedCast\(",
    r"Chars\.constrainToRange\(",
    r"Floats\.constrainToRange\(",
    r"Ascii\.toLowerCase\(",

    # Commons utils
    r"ObjectUtils\.CONST\(",
    r"ObjectUtils\.CONST_SHORT\(",
    r"ObjectUtils\.CONST_BYTE\(",
    r"Conversion\.\w+\(",
    r"EndianUtils\.\w+\(",

    # BouncyCastle
    r"GF2Field\.\w+\(",

    # Java NIO Surrogate
    r"Surrogate\.\w+\(",

    # ImPlot junk (standalone calls with no assignment)
    r"ImPlot\.getColormapColor[XY]\(",
    r"ImPlot\.getPlotPos[XY]\(",
    r"ImNodes\.getNodeDimensions[XY]\(",
    r"NodeEditor\.getNodeZPosition\(",

    # JDP
    r"JdpGenericPacket\.\w+\(",

    # Minecraft rotation/color helpers used as junk
    r"RotationPropertyHelper\.toDegrees\(",
    r"ColorHelper\.getAlphaFloat\(",
    r"Easing\.inQuart\(",

    # XML/Xerces
    r"XMLChar\.\w+\(",

    # Netty
    r"AsciiString\.toLowerCase\(",

    # FastUtil
    r"SafeMath\.\w+\(",

    # SF2
    r"SF2Region\.\w+\(",

    # BCEL internal
    r"Const\.getNoOfOperands\(",
    r"Const\.getOperandType\(",

    # CollationElementIterator
    r"CollationElementIterator\.\w+\(",

    # class_NNNN.method_NNNN (Minecraft intermediary names used as junk fillers)
    r"class_\d+\.method_\d+\(",

    # Standalone Float/Double conversion with no assignment (expression statement)
    r"^\s*Float\.intBitsToFloat\([^)]+\);$",
    r"^\s*Double\.longBitsToDouble\([^)]+\);$",

    # ImGui methods that are junk when standalone (no assignment, no condition)
    r"^\s*ImGui\.getFrameHeightWithSpacing\(\);$",
    r"^\s*ImGui\.getFrameHeight\(\);$",
]

JUNK_RE = re.compile("|".join(JUNK_API_PATTERNS), re.MULTILINE)

# Junk imports — libraries that only appear in dead code
JUNK_IMPORT_PREFIXES = [
    "com.google.common.base.Ascii",
    "com.google.common.primitives.",
    "com.ibm.icu.",
    "com.sun.media.sound.",
    "com.sun.org.apache.",
    "imgui.extension.imnodes.",
    "imgui.extension.implot.",
    "imgui.extension.nodeditor.",
    "io.netty.util.AsciiString",
    "it.unimi.dsi.fastutil.SafeMath",
    "java.text.CollationElementIterator",
    "jdk.internal.icu.",
    "org.lwjgl.system.linux.",
    "org.lwjgl.system.windows.",
    "org.lwjgl.util.freetype.",
    "org.lwjgl.stb.",
    "org.lwjgl.system.libffi.",
    "org.lwjgl.system.jni.",
    "org.lwjgl.util.nfd.",
    "net.minecraft.util.math.RotationPropertyHelper",
    "net.minecraft.client.render.entity.feature.Easing",
    "org.bouncycastle.",
    "org.apache.commons.lang3.ObjectUtils",
    "org.apache.commons.lang3.Conversion",
    "org.apache.commons.io.EndianUtils",
    "org.lwjgl.opengl.",
    "org.lwjgl.vulkan.",
    "org.lwjgl.glfw.",
    "sun.nio.cs.Surrogate",
    "java.lang.Character",  # Character.toTitleCase used as junk
]

# ZWC character
ZWC = "\u200e"
ZWC_ESCAPE = "\\u200e"

# XOR constant patterns
XOR_VIA_OR_AND = re.compile(
    r'\((\w+(?:\.\w+)?)\s*\|\s*(\w+(?:\.\w+)?)\)\s*-\s*\(\1\s*&\s*\2\)'
)


# ═══════════════════════════════════════════════════════════════════════
#  CORE: Brace-depth mapping
# ═══════════════════════════════════════════════════════════════════════

def _build_depth_map(lines: list[str]) -> list[int]:
    """Build a cumulative brace depth for each line (depth AFTER the line)."""
    depth = 0
    depths = []
    in_block_comment = False
    for line in lines:
        # Count braces outside of strings/chars/comments
        in_str = False
        in_char = False
        j = 0
        while j < len(line):
            ch = line[j]
            if in_block_comment:
                if ch == '*' and j + 1 < len(line) and line[j + 1] == '/':
                    in_block_comment = False
                    j += 2
                    continue
                j += 1
                continue
            if ch == '/' and j + 1 < len(line):
                if line[j + 1] == '/':
                    break  # rest of line is comment
                if line[j + 1] == '*':
                    in_block_comment = True
                    j += 2
                    continue
            if ch == '\\' and (in_str or in_char):
                j += 2  # skip escaped character
                continue
            if ch == '"' and not in_char:
                in_str = not in_str
            elif ch == "'" and not in_str:
                in_char = not in_char
            elif not in_str and not in_char:
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
            j += 1
        depths.append(depth)
    return depths


def _find_block_end(lines: list[str], start: int) -> int:
    """Find the line index where the block starting at `start` closes.
    The `start` line must contain a '{'. Returns the line with matching '}'."""
    depth = 0
    found_open = False
    in_block_comment = False
    for i in range(start, len(lines)):
        line = lines[i]
        in_str = False
        in_char = False
        j = 0
        while j < len(line):
            ch = line[j]
            if in_block_comment:
                if ch == '*' and j + 1 < len(line) and line[j + 1] == '/':
                    in_block_comment = False
                    j += 2
                    continue
                j += 1
                continue
            if ch == '/' and j + 1 < len(line):
                if line[j + 1] == '/':
                    break  # rest of line is comment
                if line[j + 1] == '*':
                    in_block_comment = True
                    j += 2
                    continue
            if ch == '\\' and (in_str or in_char):
                j += 2  # skip escaped character
                continue
            if ch == '"' and not in_char:
                in_str = not in_str
            elif ch == "'" and not in_str:
                in_char = not in_char
            elif not in_str and not in_char:
                if ch == '{':
                    depth += 1
                    found_open = True
                elif ch == '}':
                    depth -= 1
                    if depth == 0 and found_open:
                        return i
            j += 1
    # No matching close found — return -1 so callers can detect failure
    return -1 if not found_open else len(lines) - 1


def _block_contains_junk(lines: list[str], start: int, end: int) -> bool:
    """Check if a range of lines contains any junk API pattern."""
    block_text = '\n'.join(lines[start:end + 1])
    return bool(JUNK_RE.search(block_text))


def _block_ends_with_return(lines: list[str], start: int, end: int) -> bool:
    """Check if a block's last meaningful statement is return."""
    for i in range(end, start - 1, -1):
        s = lines[i].strip()
        if s and s != '}':
            return bool(re.match(r'return\b', s))
    return False


# ═══════════════════════════════════════════════════════════════════════
#  PASS: ZWC stripping
# ═══════════════════════════════════════════════════════════════════════

def strip_zwc(text: str) -> str:
    """Remove all Unicode ZWC characters and their escape sequences."""
    text = text.replace(ZWC_ESCAPE, "")
    text = text.replace(ZWC, "")
    return text


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Import cleanup
# ═══════════════════════════════════════════════════════════════════════

def clean_imports(text: str) -> tuple[str, int]:
    """Remove imports that are only used in junk code. Returns (text, count_removed)."""
    lines = text.split('\n')
    import_lines = []
    code_lines = []

    for line in lines:
        if line.strip().startswith('import ') or line.strip().startswith('import\t'):
            import_lines.append(line)
        else:
            code_lines.append(line)

    kept_imports = []
    removed_count = 0
    for imp in import_lines:
        is_junk = any(prefix in imp for prefix in JUNK_IMPORT_PREFIXES)
        if is_junk:
            removed_count += 1
        else:
            kept_imports.append(imp)

    result = kept_imports
    if removed_count:
        result.append(f'// [DEOBF] Removed {removed_count} junk imports (LWJGL/FreeType/ICU/Guava/etc.)')
    result.append('')
    result.extend(code_lines)
    return '\n'.join(result), removed_count


def remove_unused_imports(text: str) -> tuple[str, int]:
    """Remove imports whose class names no longer appear in the code body.
    Run this AFTER dead branch elimination to clean up imports that were
    only referenced in removed dead code."""
    lines = text.split('\n')
    import_lines = []
    import_indices = []
    code_lines = []

    for i, line in enumerate(lines):
        if line.strip().startswith('import ') or line.strip().startswith('import\t'):
            import_lines.append(line)
            import_indices.append(i)
        else:
            code_lines.append(line)

    code_text = '\n'.join(code_lines)

    kept = []
    removed = 0
    for imp in import_lines:
        # Extract simple class name from import
        # import foo.bar.Baz; → Baz
        # import foo.bar.Baz.inner; → inner
        m = re.match(r'import\s+[\w.]+\.(\w+);', imp)
        if not m:
            kept.append(imp)
            continue

        class_name = m.group(1)

        # Always keep standard java/common imports (they might be used implicitly)
        if any(imp.startswith(f'import {p}') for p in [
            'java.lang.', 'java.util.', 'java.io.',
        ]):
            kept.append(imp)
            continue

        # Check if class name appears in code (not in imports)
        # Use word boundary to avoid false matches
        if re.search(r'\b' + re.escape(class_name) + r'\b', code_text):
            kept.append(imp)
        else:
            removed += 1

    result = kept
    if removed:
        result.append(f'// [DEOBF] Removed {removed} unused imports (dead code cleanup)')
    result.append('')
    result.extend(code_lines)
    return '\n'.join(result), removed


# ═══════════════════════════════════════════════════════════════════════
#  PASS: XOR constant simplification
# ═══════════════════════════════════════════════════════════════════════

def simplify_xor_constants(text: str) -> str:
    """Simplify (A|B)-(A&B) to A^B and other constant obfuscation patterns."""
    text = XOR_VIA_OR_AND.sub(r'(\1 ^ \2)', text)

    # (int)((long)X.Y ^ (long)Z.W) → XOR_CONST(X.Y, Z.W)
    text = re.sub(
        r'\(int\)\(\(long\)(\w+\.\w+)\s*\^\s*\(long\)(\w+\.\w+)\)',
        r'CONST(\1, \2)',
        text
    )

    # (long)X.Y ^ (long)Z.W → XOR_L(X.Y, Z.W)
    text = re.sub(
        r'\(long\)(\w+\.\w+)\s*\^\s*\(long\)(\w+\.\w+)',
        r'CONST_L(\1, \2)',
        text
    )

    return text


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Dead branch elimination (the big one)
# ═══════════════════════════════════════════════════════════════════════

# Opaque predicate patterns (after ZWC stripping)
OPAQUE_IF_RE = re.compile(
    r'if\s*\('
    r'(?:'
    r'aO\.\w+\([^)]*,\s*[^)]*,\s*null,\s*null\)'  # aO.method(x, y, null, null)
    r'|'
    r'OPAQUE_PRED\('                                  # Already annotated
    r'|'
    r'ag\.\w+\([^)]*,\s*[^)]*,\s*null,\s*null\)'    # ag.method(x, y, null, null) — wrapper
    r')'
)

# Also match opaque predicates used in comparisons on the same line
OPAQUE_LINE_RE = re.compile(
    r'aO\.\w+\([^)]*,\s*[^)]*,\s*null,\s*null\)'
    r'|ag\.\w+\([^)]*,\s*[^)]*,\s*null,\s*null\)'
)


def _is_opaque_if(stripped: str) -> bool:
    """Check if a stripped line is an opaque predicate if-statement."""
    return bool(
        OPAQUE_IF_RE.search(stripped)
        or ('if (' in stripped and 'null, null)' in stripped)
        or ('if (' in stripped and 'OPAQUE_PRED(' in stripped)
    )


def _has_real_logic(lines: list[str], start: int, end: int) -> bool:
    """Check if a block contains real game/UI logic (not just wrapper calls).
    This helps disambiguate when both if and else branches look similar."""
    block_text = '\n'.join(lines[start:end + 1])
    real_patterns = [
        'ImGui.begin(', 'ImGui.end(', 'ImGui.text(', 'ImGui.textWrapped(',
        'ImGui.pushStyleColor(', 'ImGui.popStyleColor(', 'ImGui.pushStyleVar(',
        'ImGui.popStyleVar(', 'ImGui.setNextWindow', 'ImGui.setWindowFontScale(',
        'ImGui.getScrollY(', 'ImGui.getScrollMaxY(', 'ImGui.plotLines(',
        'ImGui.plotHistogram(', 'ImGui.beginTabItem(', 'ImGui.endTabItem(',
        'System.currentTimeMillis()', 'Math.abs(', 'Math.min(', 'Math.max(',
        '.contains(', 'Arrays.', 'Objects.', '.get()', '.set(',
        'System.arraycopy(', '.length', '.size()',
        'Float.intBitsToFloat(',  # Used in real ImGui calls with style values
    ]
    return any(p in block_text for p in real_patterns)


def eliminate_dead_branches(text: str) -> tuple[str, int]:
    """Multi-pass dead branch elimination. Returns (text, total_removed).

    Key insight: In Bozar-obfuscated code, EVERY if-block guarded by an
    opaque predicate (aO.method(x, y, null, null)) that ends with return;
    is dead code. The opaque predicate is a constant that always skips the
    block. The return; prevents fall-through to real code.
    """
    total_removed = 0

    for pass_num in range(15):
        lines = text.split('\n')
        dead_ranges = []
        removed_this_pass = 0

        i = 0
        while i < len(lines):
            stripped = lines[i].strip()

            # --- Strategy 1: OPAQUE if-block with return → DEAD ---
            if _is_opaque_if(stripped):
                if '{' in lines[i]:
                    block_end = _find_block_end(lines, i)
                elif i + 1 < len(lines) and '{' in lines[i + 1]:
                    block_end = _find_block_end(lines, i + 1)
                else:
                    # Single-line: if (OPAQUE) something;
                    if stripped.endswith(';') or '** GOTO' in stripped:
                        dead_ranges.append((i, i, None))
                        removed_this_pass += 1
                    i += 1
                    continue

                if block_end <= i:
                    i += 1
                    continue

                has_return = _block_ends_with_return(lines, i, block_end)
                has_junk = _block_contains_junk(lines, i, block_end)
                has_goto = any('** GOTO' in lines[k] for k in range(i, block_end + 1))
                has_break = any(lines[k].strip().startswith('break ') for k in range(i, block_end + 1))

                # Check for else
                next_line = block_end + 1
                has_else = (next_line < len(lines) and
                            (lines[next_line].strip().startswith('else') or
                             lines[next_line].strip() == '} else {'))

                if has_junk:
                    # Definitely dead — contains known junk API calls
                    if has_else:
                        else_end = _find_block_end(lines, next_line)
                        else_body = _extract_block_body(lines, next_line, else_end)
                        dead_ranges.append((i, else_end, else_body))
                        i = else_end + 1
                    else:
                        dead_ranges.append((i, block_end, None))
                        i = block_end + 1
                    removed_this_pass += 1
                    continue

                elif has_return and not has_else:
                    # Opaque if with return and no else → dead
                    # The return prevents reaching real code below
                    dead_ranges.append((i, block_end, None))
                    removed_this_pass += 1
                    i = block_end + 1
                    continue

                elif has_return and has_else:
                    # Both branches exist — determine which is dead
                    else_end = _find_block_end(lines, next_line)
                    else_has_junk = _block_contains_junk(lines, next_line, else_end)
                    else_has_return = _block_ends_with_return(lines, next_line, else_end)
                    if_has_real = _has_real_logic(lines, i, block_end)
                    else_has_real = _has_real_logic(lines, next_line, else_end)

                    if else_has_junk and not has_junk:
                        # Else is dead, if is live
                        if_body = _extract_block_body(lines, i, block_end)
                        dead_ranges.append((i, else_end, if_body))
                        removed_this_pass += 1
                        i = else_end + 1
                        continue
                    elif not if_has_real and else_has_real:
                        # If-block has no real logic, else does → if is dead
                        else_body = _extract_block_body(lines, next_line, else_end)
                        dead_ranges.append((i, else_end, else_body))
                        removed_this_pass += 1
                        i = else_end + 1
                        continue
                    elif if_has_real and not else_has_real and else_has_return:
                        # If has real logic, else doesn't → else is dead
                        if_body = _extract_block_body(lines, i, block_end)
                        dead_ranges.append((i, else_end, if_body))
                        removed_this_pass += 1
                        i = else_end + 1
                        continue
                    elif not if_has_real and not else_has_real:
                        # Neither has real logic — if-block is dead (default for Bozar)
                        else_body = _extract_block_body(lines, next_line, else_end)
                        dead_ranges.append((i, else_end, else_body))
                        removed_this_pass += 1
                        i = else_end + 1
                        continue

                elif (has_goto or has_break) and not has_else:
                    # Opaque if with GOTO/break and no else → dead
                    dead_ranges.append((i, block_end, None))
                    removed_this_pass += 1
                    i = block_end + 1
                    continue

            # --- Strategy 2: Standalone junk lines ---
            if JUNK_RE.search(stripped) and stripped.endswith(';'):
                if not re.search(r'(?:=|if\s*\(|while\s*\(|for\s*\(|&&|\|\|)', stripped):
                    dead_ranges.append((i, i, None))
                    removed_this_pass += 1
                    i += 1
                    continue

            # --- Strategy 3: Opaque predicate on GOTO lines ---
            if '** GOTO' in stripped and OPAQUE_LINE_RE.search(stripped):
                dead_ranges.append((i, i, None))
                removed_this_pass += 1
                i += 1
                continue

            # --- Strategy 4: CFF while-switch trampolines (small) ---
            if re.match(r'\s*\w+:\s*while\s*\(true\)\s*\{', stripped):
                block_end = _find_block_end(lines, i)
                if block_end and block_end - i <= 12:
                    block_text = '\n'.join(lines[i:block_end + 1])
                    if ('default:' in block_text and 'continue' in block_text
                            and 'case ' in block_text):
                        dead_ranges.append((i, block_end, None))
                        removed_this_pass += 1
                        i = block_end + 1
                        continue

            i += 1

        if removed_this_pass == 0:
            break

        # Apply removals in reverse order to preserve line numbers
        dead_ranges.sort(key=lambda x: x[0], reverse=True)
        for start, end, replacement in dead_ranges:
            indent = len(lines[start]) - len(lines[start].lstrip()) if lines[start].strip() else 8
            if replacement:
                lines[start:end + 1] = [' ' * indent + '// [DEOBF] Dead branch removed'] + replacement
            else:
                lines[start:end + 1] = [' ' * indent + '// [DEOBF] Dead branch removed']

        total_removed += removed_this_pass
        text = '\n'.join(lines)

    return text, total_removed


def _extract_block_body(lines: list[str], start: int, end: int) -> list[str]:
    """Extract the body of a block, stripping the if/else/brace wrapper.
    Only strips the first and last lines of the range (the wrapper lines)."""
    body = []
    for j in range(start, end + 1):
        s = lines[j].strip()
        # Skip the opening line (if/else/} else { + brace)
        if j == start and (s.startswith('if ') or s.startswith('else') or
                           s.startswith('} else') or s == '{'):
            continue
        # Skip standalone opening brace right after start
        if j == start + 1 and s == '{':
            continue
        # Skip the closing brace
        if j == end and (s == '}' or s == '};'):
            continue
        body.append(lines[j])
    return body


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Orphan dead code cleanup
# ═══════════════════════════════════════════════════════════════════════

def cleanup_orphan_dead_code(text: str) -> tuple[str, int]:
    """Remove orphaned dead code patterns that survived the main pass.
    These include:
    - Opaque predicate if-blocks without proper braces (broken decompiler output)
    - Lines between OPAQUE_PRED and return; that are clearly dead
    - ** while (OPAQUE_PRED) lines
    - Unreachable code after return; in same scope
    """
    lines = text.split('\n')
    result = []
    removed = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        has_opaque = ('OPAQUE_PRED' in stripped or
                      ('aO.' in stripped and 'null, null)' in stripped) or
                      ('ag.' in stripped and 'null, null)' in stripped))

        # Pattern: ** while (OPAQUE) → dead loop, remove
        if stripped.startswith('** while') and has_opaque:
            indent = len(lines[i]) - len(lines[i].lstrip())
            result.append(' ' * indent + '// [DEOBF] Dead opaque while removed')
            removed += 1
            i += 1
            continue

        # Pattern: if (OPAQUE) { wrapper; wrapper; return; }
        # where the block doesn't have proper structure
        if has_opaque and stripped.startswith('if '):
            # Scan ahead for return; within 8 lines
            scan_end = min(len(lines), i + 8)
            found_return = False
            return_line = -1
            for k in range(i + 1, scan_end):
                if 'return;' in lines[k]:
                    found_return = True
                    return_line = k
                    break
                if lines[k].strip().startswith('if ') or lines[k].strip().startswith('for '):
                    break

            if found_return:
                # Check if there's real logic between opaque and return
                block_text = '\n'.join(lines[i:return_line + 1])
                has_real = _has_real_logic(lines, i, return_line)
                if not has_real:
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    result.append(' ' * indent + '// [DEOBF] Dead branch removed')
                    removed += 1
                    i = return_line + 1
                    continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), removed


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Aggressive dead block removal (post-first-pass cleanup)
# ═══════════════════════════════════════════════════════════════════════

def aggressive_junk_block_removal(text: str) -> tuple[str, int]:
    """Second-stage: find ANY if-block containing junk patterns, even without
    the standard opaque predicate form. This catches deeply nested dead code
    that the first pass missed because the opaque predicate was on a different line."""
    total = 0

    for _ in range(10):
        lines = text.split('\n')
        removed = 0
        i = 0
        new_lines = []

        while i < len(lines):
            stripped = lines[i].strip()

            # Find if-blocks containing junk
            if re.match(r'\s*if\s*\(', stripped) and '{' in stripped:
                block_end = _find_block_end(lines, i)
                if block_end > i and block_end - i < 20:
                    has_junk = _block_contains_junk(lines, i, block_end)
                    has_return = _block_ends_with_return(lines, i, block_end)

                    if has_junk and has_return:
                        indent = len(lines[i]) - len(lines[i].lstrip())
                        new_lines.append(' ' * indent + '// [DEOBF] Dead block removed')
                        removed += 1

                        # Skip past any else block too if it exists
                        next_i = block_end + 1
                        if (next_i < len(lines) and
                                lines[next_i].strip().startswith('else')):
                            else_end = _find_block_end(lines, next_i)
                            # Check if else is junk too
                            if _block_contains_junk(lines, next_i, else_end):
                                i = else_end + 1
                            else:
                                # Keep else body
                                for j in range(next_i, else_end + 1):
                                    s = lines[j].strip()
                                    if s in ('else {', '} else {', '}'):
                                        continue
                                    new_lines.append(lines[j])
                                i = else_end + 1
                        else:
                            i = block_end + 1
                        continue

            new_lines.append(lines[i])
            i += 1

        total += removed
        text = '\n'.join(new_lines)
        if removed == 0:
            break

    return text, total


# ═══════════════════════════════════════════════════════════════════════
#  PASS: CFF switch-case dead branch removal
# ═══════════════════════════════════════════════════════════════════════

def remove_cff_dead_cases(text: str) -> tuple[str, int]:
    """Remove dead case blocks within CFF switch statements.
    These are switch cases that contain junk + return."""
    lines = text.split('\n')
    result = []
    removed = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        # Match: case NNNN: { ... junk ... return; ... }
        if re.match(r'case\s+[\-\d]+:\s*\{', stripped):
            block_end = _find_block_end(lines, i)
            if block_end > i:
                has_junk = _block_contains_junk(lines, i, block_end)
                has_return = _block_ends_with_return(lines, i, block_end)
                if has_junk and has_return:
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    result.append(' ' * indent + '// [DEOBF] Dead CFF case removed')
                    removed += 1
                    i = block_end + 1
                    continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), removed


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Remove opaque predicate wrapper methods
# ═══════════════════════════════════════════════════════════════════════

def remove_opaque_wrappers(text: str) -> tuple[str, int]:
    """Remove methods that are just wrappers around aO.method calls."""
    lines = text.split('\n')
    result = []
    removed = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        # Match: private/public static TYPE method(int, int, TYPE, TYPE) {
        #            return aO.method(n, n2, arg3, arg4);
        #        }
        m = re.match(r'(private|public)\s+static\s+\w+\s+(\w+)\s*\([^)]*\)\s*\{', stripped)
        if m:
            # Check if the body is a single aO.method call
            j = i + 1
            body_lines = []
            while j < len(lines) and lines[j].strip() != '}':
                if lines[j].strip():
                    body_lines.append(lines[j].strip())
                j += 1

            if (len(body_lines) == 1 and
                    re.match(r'return\s+aO\.\w+\(', body_lines[0])):
                indent = len(lines[i]) - len(lines[i].lstrip())
                result.append(f'{" " * indent}// [DEOBF] Opaque predicate wrapper removed: {m.group(2)}')
                removed += 1
                i = j + 1
                continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), removed


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Annotate wrapper methods
# ═══════════════════════════════════════════════════════════════════════

def annotate_wrappers(text: str) -> tuple[str, int]:
    """Identify and annotate single-line wrapper methods that just delegate."""
    lines = text.split('\n')
    wrappers = {}

    # First pass: identify wrappers
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()

        m = re.match(r'(private|public)\s+static\s+\w+\s+(\w+)\s*\([^)]*\)\s*\{', stripped)
        if m:
            method_name = m.group(2)
            body_lines = []
            j = i + 1
            while j < len(lines) and lines[j].strip() != '}':
                if lines[j].strip():
                    body_lines.append(lines[j].strip())
                j += 1

            if len(body_lines) == 1:
                body = body_lines[0]
                target = re.search(r'(?:return\s+)?(\w+\.\w+)\(', body)
                if target:
                    wrappers[method_name] = target.group(1)
        i += 1

    # Second pass: annotate
    result = []
    count = 0
    for line in lines:
        annotated = False
        for wrapper_name, target in wrappers.items():
            if f' {wrapper_name}(' in line and 'static' in line:
                result.append(line + f'  // [DEOBF] Wrapper -> {target}')
                annotated = True
                count += 1
                break
        if not annotated:
            result.append(line)

    return '\n'.join(result), count


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Label string contexts
# ═══════════════════════════════════════════════════════════════════════

def label_string_contexts(text: str) -> tuple[str, int]:
    """Label iWQ[] string references by their usage context."""
    lines = text.split('\n')
    result = []
    count = 0

    for line in lines:
        label = None
        if 'ImGui.begin(' in line and 'iWQ[' in line:
            label = 'window title'
        elif '.contains(' in line and 'iWQ[' in line:
            label = 'log keyword filter'
        elif 'textWrapped' in line and 'iWQ[' in line:
            label = 'display text'
        elif re.search(r'af[RQSTUV]\(', line) and 'iWQ[' in line:
            label = 'format template'
        elif 'plotLines' in line and 'iWQ[' in line:
            label = 'graph label'
        elif 'plotHistogram' in line and 'iWQ[' in line:
            label = 'histogram label'
        elif 'beginTabItem' in line and 'iWQ[' in line:
            label = 'tab name'
        elif 'text(' in line and 'iWQ[' in line:
            label = 'UI text'

        if label:
            line = line.rstrip() + f'  // [DEOBF] String: {label}'
            count += 1
        result.append(line)

    return '\n'.join(result), count


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Annotate cipher and opaque calls
# ═══════════════════════════════════════════════════════════════════════

def annotate_cipher(text: str) -> str:
    """Annotate the string decryption method with human-readable comments."""
    text = text.replace(
        'private static String afW(char[] cArray, long l, int n) {',
        '// [DEOBF] String decryption -- rolling XOR cipher with bit rotation\n'
        '// Cipher: for each char, key = f(position, l, n) with bit rotation;\n'
        '//         char[i] ^= key; key evolves per iteration.\n'
        '// To decrypt: need char array + long seed + int seed from other classes.\n'
        'private static String decryptString(char[] cArray, long seed_l, int seed_n) {'
    )
    return text


def annotate_opaque_calls(text: str) -> str:
    """Replace remaining aO.method(x, y, null, null) with OPAQUE_PRED label."""
    text = re.sub(
        r'aO\.(\w+)\(([^,]+),\s*([^,]+),\s*null,\s*null\)',
        r'OPAQUE_PRED(\2, \3)  /* aO.\1 */',
        text
    )
    return text


# ═══════════════════════════════════════════════════════════════════════
#  PASS: Remove empty blocks and cleanup
# ═══════════════════════════════════════════════════════════════════════

def simplify_cff_blocks(text: str) -> tuple[str, int]:
    """Simplify CFF while-switch blocks by removing trampoline cases."""
    lines = text.split('\n')
    result = []
    simplified = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        # CFF trampoline case: case N: { n = ...; continue blockX; }
        if re.match(r'case\s+[\-\d]+:\s*\{', stripped):
            # Look ahead for the pattern: set variable + continue
            block_end = _find_block_end(lines, i)
            if block_end and block_end - i <= 5:
                block_text = '\n'.join(lines[i:block_end + 1])
                if 'continue block' in block_text and 'return' not in block_text:
                    # This is a trampoline case — skip it
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    result.append(' ' * indent + '// [DEOBF] CFF trampoline case removed')
                    simplified += 1
                    i = block_end + 1
                    continue

        # CFF default: { continue blockX; } — dispatch mechanism
        if re.match(r'default:\s*\{', stripped):
            block_end = _find_block_end(lines, i)
            if block_end and block_end - i <= 3:
                block_text = '\n'.join(lines[i:block_end + 1])
                if 'continue block' in block_text:
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    result.append(' ' * indent + '// [DEOBF] CFF dispatch removed')
                    simplified += 1
                    i = block_end + 1
                    continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), simplified


def remove_unreachable_after_deobf(text: str) -> tuple[str, int]:
    """Remove code lines between a DEOBF dead branch comment and the next
    structural element (closing brace, case, else, etc.). These are orphaned
    statements from partially removed dead blocks."""
    lines = text.split('\n')
    result = []
    removed = 0
    i = 0

    while i < len(lines):
        stripped = lines[i].strip()

        if stripped == '// [DEOBF] Dead branch removed':
            result.append(lines[i])
            i += 1
            # Skip orphaned lines until we hit structure
            while i < len(lines):
                next_s = lines[i].strip()
                # Stop at: closing brace, case, else, method def, another DEOBF, blank line after brace
                if (next_s.startswith('}') or
                    next_s.startswith('case ') or
                    next_s.startswith('else') or
                    next_s.startswith('default:') or
                    next_s.startswith('// [DEOBF]') or
                    next_s.startswith('private ') or
                    next_s.startswith('public ') or
                    next_s.startswith('static ') or
                    next_s.startswith('block') or
                    next_s.startswith('break') or
                    not next_s):
                    break
                # This is an orphaned line — remove it
                removed += 1
                i += 1
            continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), removed


def cleanup_empty_blocks(text: str) -> str:
    """Remove consecutive DEOBF comments, empty blocks, and lone braces."""
    lines = text.split('\n')
    result = []
    prev_was_deobf = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        is_deobf = '// [DEOBF]' in line and stripped.startswith('//')

        # Skip consecutive DEOBF-only lines
        if is_deobf and prev_was_deobf:
            continue

        # Skip lone closing braces after DEOBF comments
        if stripped == '}' and prev_was_deobf:
            continue

        # Skip empty case labels with no body (case N: followed by only DEOBF or })
        if re.match(r'case\s+[\-\d]+:\s*$', stripped):
            # Check if next non-blank line is just DEOBF or }
            next_idx = i + 1
            while next_idx < len(lines) and not lines[next_idx].strip():
                next_idx += 1
            if next_idx < len(lines):
                next_s = lines[next_idx].strip()
                if next_s.startswith('// [DEOBF]') or next_s == '}' or next_s.startswith('case '):
                    continue

        result.append(line)
        prev_was_deobf = is_deobf

    text = '\n'.join(result)

    # Remove multiple consecutive blank lines
    text = re.sub(r'\n{3,}', '\n\n', text)

    return text


# ═══════════════════════════════════════════════════════════════════════
#  STATISTICS
# ═══════════════════════════════════════════════════════════════════════

def generate_stats(original: str, cleaned: str, details: dict) -> str:
    """Generate deobfuscation statistics."""
    orig_lines = len(original.split('\n'))
    clean_lines = len(cleaned.split('\n'))
    reduction = (orig_lines - clean_lines) / orig_lines * 100 if orig_lines else 0

    orig_zwc = original.count(ZWC) + original.count(ZWC_ESCAPE)

    check = lambda v: 'X' if v else ' '

    stats = f"""
 UNIVERSAL DEOBFUSCATION REPORT v4.0
 ================================

  Original lines:        {orig_lines}
  Cleaned lines:         {clean_lines}
  Lines reduced:         {orig_lines - clean_lines} ({reduction:.1f}%)

  ZWC characters removed:     {orig_zwc}
  Junk imports removed:       {details.get('imports', 0)}
  Dead branches eliminated:   {details.get('dead_branches', 0)}
  Aggressive blocks removed:  {details.get('aggressive', 0)}
  CFF dead cases removed:     {details.get('cff_cases', 0)}
  Opaque wrappers removed:    {details.get('opaque_wrappers', 0)}
  Wrapper methods annotated:  {details.get('wrappers', 0)}
  String contexts labeled:    {details.get('strings', 0)}

  Obfuscation layers handled:
    [{check(orig_zwc)}] Unicode ZWC naming
    [{check(details.get('dead_branches', 0))}] Opaque predicates / dead branches
    [{check(details.get('cff_cases', 0))}] Control flow flattening (CFF)
    [X] XOR constant simplification
    [{check(details.get('opaque_wrappers', 0))}] Opaque predicate wrapper removal
    [{check(details.get('wrappers', 0))}] Wrapper method annotation
    [{check(details.get('strings', 0))}] String context labeling
    [{check(details.get('imports', 0))}] Junk import removal
"""
    return stats


# ═══════════════════════════════════════════════════════════════════════
#  CONFIDENCE ASSESSMENT
# ═══════════════════════════════════════════════════════════════════════

def assess_confidence(original: str, cleaned: str, details: dict) -> dict:
    """Evaluate how confident we are that the deobfuscation is complete.

    Returns a dict with:
      - confidence: float 0.0-1.0
      - level: 'HIGH' | 'MEDIUM' | 'LOW'
      - issues: list of strings describing remaining problems
      - recommend_fallback: bool — True if java-deobfuscator should run
    """
    issues = []
    score = 1.0  # Start at 100%, deduct for problems

    orig_lines = len(original.split('\n'))
    clean_lines = len(cleaned.split('\n'))
    reduction = (orig_lines - clean_lines) / orig_lines if orig_lines else 0

    # --- Check remaining opaque predicates ---
    remaining_opaques = (
        cleaned.count('OPAQUE_PRED(') +
        len(re.findall(r'aO\.\w+\([^)]*null,\s*null\)', cleaned))
    )
    if remaining_opaques > 10:
        score -= 0.25
        issues.append(f"{remaining_opaques} opaque predicates still present")
    elif remaining_opaques > 3:
        score -= 0.10
        issues.append(f"{remaining_opaques} opaque predicates still present")
    elif remaining_opaques > 0:
        score -= 0.03
        issues.append(f"{remaining_opaques} opaque predicates still present (minor)")

    # --- Check remaining junk API calls ---
    remaining_junk = len(JUNK_RE.findall(cleaned))
    if remaining_junk > 5:
        score -= 0.20
        issues.append(f"{remaining_junk} junk API calls still in output")
    elif remaining_junk > 0:
        score -= 0.05
        issues.append(f"{remaining_junk} junk API calls still in output (minor)")

    # --- Check code reduction ---
    # Exclude imports for code body reduction
    orig_code = len([l for l in original.split('\n') if not l.startswith('import ')])
    clean_code = len([l for l in cleaned.split('\n') if not l.startswith('import ')])
    code_reduction = (orig_code - clean_code) / orig_code if orig_code else 0

    if code_reduction < 0.30:
        score -= 0.30
        issues.append(f"Low code reduction ({code_reduction:.0%}) — many dead branches may remain")
    elif code_reduction < 0.50:
        score -= 0.15
        issues.append(f"Moderate code reduction ({code_reduction:.0%}) — some dead code may remain")

    # --- Check obfuscator-specific indicators ---
    detected = details.get('detected_obfuscators', {})
    is_bozar = detected.get('bozar', 0) > 0.3

    # ZWC check only penalizes for Bozar-detected code
    orig_zwc = original.count(ZWC) + original.count(ZWC_ESCAPE)
    # Also check extended ZWC
    for c in ZWC_ALL:
        orig_zwc += original.count(c)
    if orig_zwc == 0 and is_bozar:
        score -= 0.15
        issues.append("No ZWC characters found despite Bozar detection")

    # Dead branch check — only for Bozar
    dead_branches = details.get('dead_branches', 0)
    if dead_branches == 0 and orig_zwc > 0:
        score -= 0.20
        issues.append("No dead branches eliminated despite Bozar indicators")

    # --- JNIC detection — fundamentally limits Java-level deobfuscation ---
    if detected.get('jnic', 0) > 0.3:
        jnic_count = details.get('jnic_natives', 0)
        if jnic_count > 0:
            score -= 0.30
            issues.append(f"JNIC/native obfuscation: {jnic_count} methods hidden in native code (cannot deobfuscate at Java level)")

    # --- Paramorphism/Binscure — decompiler failures ---
    if detected.get('paramorphism', 0) > 0.3 or detected.get('binscure', 0) > 0.3:
        error_count = details.get('decompiler_errors', 0)
        if error_count > 5:
            score -= 0.20
            issues.append(f"{error_count} decompiler errors — anti-decompilation techniques detected")
        elif error_count > 0:
            score -= 0.10
            issues.append(f"{error_count} decompiler errors (partial decompilation)")

    # --- Check CFF while-true loops remaining ---
    remaining_cff = cleaned.count('while (true)')
    if remaining_cff > 10:
        score -= 0.15
        issues.append(f"{remaining_cff} CFF while-true loops still present")
    elif remaining_cff > 3:
        score -= 0.05
        issues.append(f"{remaining_cff} CFF while-true loops still present")

    # --- Check remaining encrypted strings (generic) ---
    encrypted_strings = len(re.findall(
        r'afW\(|decryptString\(|Cipher\.getInstance|SecretKeySpec|'
        r'invokedynamic.*String|DecryptionAgent',
        cleaned))
    if encrypted_strings > 20:
        score -= 0.10
        issues.append(f"{encrypted_strings} encrypted string calls (need full JAR to decrypt)")
    elif encrypted_strings > 5:
        score -= 0.05
        issues.append(f"{encrypted_strings} encrypted string calls remaining")

    # --- Check MBA patterns remaining ---
    remaining_mba = len(re.findall(
        r'\(\w+\s*[\^&|]\s*\w+\)\s*\+\s*\d*\s*\*?\s*\(\w+\s*[\^&|]\s*\w+\)',
        cleaned))
    if remaining_mba > 5:
        score -= 0.05
        issues.append(f"{remaining_mba} MBA expressions still present")

    # Clamp
    score = max(0.0, min(1.0, score))

    if score >= 0.80:
        level = 'HIGH'
    elif score >= 0.55:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    # Recommend fallback if confidence is not high, input is a JAR,
    # or significant issues remain
    recommend_fallback = score < 0.75

    return {
        'confidence': score,
        'level': level,
        'issues': issues,
        'recommend_fallback': recommend_fallback,
        'code_reduction': code_reduction,
        'remaining_opaques': remaining_opaques,
        'remaining_junk': remaining_junk,
    }


# ═══════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════════════

def deobfuscate(input_path: str, output_path: Optional[str] = None,
                verbose: bool = False) -> tuple[str, dict]:
    """Main deobfuscation pipeline.

    Returns:
        (output_path, confidence_info) where confidence_info is the dict
        from assess_confidence().
    """
    # Safety: check file size before reading (prevent OOM on huge/malicious files)
    file_size = os.path.getsize(input_path)
    MAX_SIZE = 50 * 1024 * 1024  # 50 MB
    if file_size > MAX_SIZE:
        raise ValueError(f"File too large ({file_size / 1024 / 1024:.1f} MB, max {MAX_SIZE // 1024 // 1024} MB)")

    try:
        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            original = f.read()
    except (PermissionError, OSError) as e:
        raise ValueError(f"Cannot read input file: {e}")

    if verbose:
        print(f"[*] Read {len(original)} bytes, {len(original.splitlines())} lines from {input_path}")

    text = original
    details = {}

    # === PHASE 0: Fingerprint obfuscator(s) ===
    if verbose:
        print("[*] Phase 0: Fingerprinting obfuscator...")
    detected = fingerprint_obfuscator(text)
    details['detected_obfuscators'] = detected
    if verbose:
        if detected:
            for name, conf in sorted(detected.items(), key=lambda x: -x[1]):
                print(f"    {name}: {conf:.0%} confidence")
        else:
            print("    No known obfuscator detected — running generic passes")

    # Pass 1: Strip ALL ZWC characters (extended set of 19 chars)
    if verbose:
        print("[*] Pass 1: Stripping Unicode ZWC characters (extended)...")
    text, n_zwc_ext = extended_zwc_strip(text)
    text = strip_zwc(text)  # Also run original for escaped forms
    if verbose and n_zwc_ext:
        print(f"    Extended ZWC: stripped {n_zwc_ext} additional invisible chars")

    # Pass 1b: Cyrillic homoglyph cleanup (Allatori, custom)
    text, n_cyrillic = cyrillic_homoglyph_cleanup(text)
    details['cyrillic_homoglyphs'] = n_cyrillic
    if verbose and n_cyrillic:
        print(f"    Cyrillic homoglyphs: normalized {n_cyrillic} lookalike chars")

    # Pass 2: Clean junk imports
    if verbose:
        print("[*] Pass 2: Removing junk imports...")
    text, n = clean_imports(text)
    details['imports'] = n
    if verbose:
        print(f"    Removed {n} junk imports")

    # Pass 3: Simplify XOR constants
    if verbose:
        print("[*] Pass 3: Simplifying XOR constant patterns...")
    text = simplify_xor_constants(text)

    # Pass 4: Remove opaque predicate wrapper methods
    if verbose:
        print("[*] Pass 4: Removing opaque predicate wrapper methods...")
    text, n = remove_opaque_wrappers(text)
    details['opaque_wrappers'] = n
    if verbose:
        print(f"    Removed {n} opaque wrapper methods")

    # Pass 5: Eliminate dead branches (multi-pass)
    if verbose:
        print("[*] Pass 5: Eliminating dead branches (multi-pass)...")
    text, n = eliminate_dead_branches(text)
    details['dead_branches'] = n
    if verbose:
        print(f"    Eliminated {n} dead branches")

    # Pass 6: Aggressive junk block removal
    if verbose:
        print("[*] Pass 6: Aggressive junk block removal...")
    text, n = aggressive_junk_block_removal(text)
    details['aggressive'] = n
    if verbose:
        print(f"    Removed {n} additional dead blocks")

    # Pass 6b: Orphan dead code cleanup
    if verbose:
        print("[*] Pass 6b: Cleaning up orphan dead code...")
    text, n = cleanup_orphan_dead_code(text)
    details['orphan'] = n
    if verbose:
        print(f"    Removed {n} orphan dead code blocks")

    # Pass 7: CFF dead case removal
    if verbose:
        print("[*] Pass 7: Removing CFF dead switch cases...")
    text, n = remove_cff_dead_cases(text)
    details['cff_cases'] = n
    if verbose:
        print(f"    Removed {n} dead CFF cases")

    # Pass 7b: Simplify CFF blocks
    if verbose:
        print("[*] Pass 7b: Simplifying CFF trampoline structures...")
    text, n = simplify_cff_blocks(text)
    details['cff_trampolines'] = n
    if verbose:
        print(f"    Simplified {n} CFF trampolines")

    # Pass 7c: Remove unused imports (after dead code removal)
    if verbose:
        print("[*] Pass 7c: Removing unused imports...")
    text, n = remove_unused_imports(text)
    details['unused_imports'] = n
    if verbose:
        print(f"    Removed {n} unused imports")

    # Pass 8: Annotate wrapper methods
    if verbose:
        print("[*] Pass 8: Identifying wrapper methods...")
    text, n = annotate_wrappers(text)
    details['wrappers'] = n
    if verbose:
        print(f"    Annotated {n} wrappers")

    # Pass 9: Label string contexts
    if verbose:
        print("[*] Pass 9: Labeling string usage contexts...")
    text, n = label_string_contexts(text)
    details['strings'] = n

    # Pass 10: Annotate cipher and opaque calls
    if verbose:
        print("[*] Pass 10: Annotating cipher and opaque predicate calls...")
    text = annotate_cipher(text)
    text = annotate_opaque_calls(text)

    # Pass 10b: Remove unreachable code after DEOBF markers
    if verbose:
        print("[*] Pass 10b: Removing unreachable orphan code...")
    text, n = remove_unreachable_after_deobf(text)
    details['orphan_code'] = n
    if verbose:
        print(f"    Removed {n} orphan code lines")

    # === PHASE 2: Obfuscator-specific passes (non-Bozar) ===
    if verbose:
        print("\n[*] === Phase 2: Obfuscator-specific passes ===")

    if detected.get('zkm', 0) > 0.2:
        if verbose:
            print("[*] Running ZKM flow deobfuscation...")
        text, n = zkm_flow_deobfuscation(text)
        details['zkm_flow'] = n
        if verbose and n:
            print(f"    Removed {n} ZKM flow patterns")

    if detected.get('allatori', 0) > 0.2:
        if verbose:
            print("[*] Running Allatori string deobfuscation...")
        text, n = allatori_string_deobfuscation(text)
        details['allatori_strings'] = n
        if verbose and n:
            print(f"    Decoded {n} Allatori patterns")

    if detected.get('skidfuscator', 0) > 0.2:
        if verbose:
            print("[*] Running Skidfuscator exception flow cleanup...")
        text, n = skidfuscator_exception_flow_cleanup(text)
        details['skidfuscator_flow'] = n
        if verbose and n:
            print(f"    Simplified {n} exception flow patterns")

    if detected.get('radon', 0) > 0.2:
        if verbose:
            print("[*] Running Radon number deobfuscation...")
        text, n = radon_number_deobfuscation(text)
        details['radon_numbers'] = n
        if verbose and n:
            print(f"    Resolved {n} Radon number patterns")

    # dProtect/qProtect: MBA simplification
    if detected.get('dprotect', 0) > 0.2 or detected.get('qprotect', 0) > 0.2:
        if verbose:
            print("[*] Running MBA expression simplification...")
        text, n = mba_simplify(text)
        details['mba_simplified'] = n
        if verbose and n:
            print(f"    Simplified {n} MBA expressions")

    # JNIC detection
    if detected.get('jnic', 0) > 0.2:
        if verbose:
            print("[*] Detecting JNIC/native obfuscation...")
        text, n = jnic_detection_annotation(text)
        details['jnic_natives'] = n
        if verbose and n:
            print(f"    Flagged {n} native method stubs (code hidden in .dll/.so)")

    # Paramorphism/Binscure: decompiler error annotation
    if detected.get('paramorphism', 0) > 0.2 or detected.get('binscure', 0) > 0.2:
        if verbose:
            print("[*] Annotating decompiler failures...")
        text, n = decompiler_error_annotation(text)
        details['decompiler_errors'] = n
        if verbose and n:
            print(f"    Found {n} decompiler errors")

    # === PHASE 3: Generic passes (always run) ===
    if verbose:
        print("\n[*] === Phase 3: Generic deobfuscation passes ===")

    if verbose:
        print("[*] Generic: String deobfuscation...")
    text, n = generic_string_deobfuscation(text)
    details['generic_strings'] = n
    if verbose and n:
        print(f"    Decoded {n} string patterns")

    if verbose:
        print("[*] Generic: Stack string reconstruction...")
    text, n = stack_string_reconstruction(text)
    details['stack_strings'] = n
    if verbose and n:
        print(f"    Reconstructed {n} stack strings")

    if verbose:
        print("[*] Generic: URLDecoder resolution...")
    text, n = url_decoder_resolution(text)
    details['url_decoded'] = n
    if verbose and n:
        print(f"    Resolved {n} URLDecoder calls")

    if verbose:
        print("[*] Generic: Bitwise NOT byte resolution...")
    text, n = bitwise_not_byte_resolution(text)
    details['bitwise_not'] = n
    if verbose and n:
        print(f"    Resolved {n} bitwise NOT patterns")

    if verbose:
        print("[*] Generic: Number deobfuscation...")
    text, n = generic_number_deobfuscation(text)
    details['number_deobf'] = n
    if verbose and n:
        print(f"    Resolved {n} Float/Double constants")

    if verbose:
        print("[*] Generic: Integer/Long reverse resolution...")
    text, n = integer_reverse_resolution(text)
    details['int_reverse'] = n
    if verbose and n:
        print(f"    Resolved {n} Integer/Long.reverse calls")

    if verbose:
        print("[*] Generic: Character arithmetic resolution...")
    text, n = char_arithmetic_resolution(text)
    details['char_arith'] = n
    if verbose and n:
        print(f"    Resolved {n} character arithmetic patterns")

    if verbose:
        print("[*] Generic: Bitwise shift resolution...")
    text, n = bitwise_shift_resolution(text)
    details['bitwise_shifts'] = n
    if verbose and n:
        print(f"    Resolved {n} bitwise shift expressions")

    if verbose:
        print("[*] Generic: MBA simplification (all code)...")
    text, n = mba_simplify(text)
    details['mba_generic'] = details.get('mba_generic', 0) + n
    if verbose and n:
        print(f"    Simplified {n} MBA expressions")

    if verbose:
        print("[*] Generic: Ternary constant resolution...")
    text, n = ternary_constant_resolution(text)
    details['ternary_resolved'] = n
    if verbose and n:
        print(f"    Resolved {n} ternary constants")

    if verbose:
        print("[*] Generic: Math opaque predicate elimination...")
    text, n = math_opaque_predicate_elimination(text)
    details['math_opaques'] = n
    if verbose and n:
        print(f"    Eliminated {n} mathematical opaque predicates")

    if verbose:
        print("[*] Generic: Bogus loop removal...")
    text, n = bogus_loop_removal(text)
    details['bogus_loops'] = n
    if verbose and n:
        print(f"    Removed {n} bogus loops")

    if verbose:
        print("[*] Generic: Synchronized junk removal...")
    text, n = synchronized_junk_removal(text)
    details['sync_junk'] = n
    if verbose and n:
        print(f"    Removed {n} junk synchronized blocks")

    if verbose:
        print("[*] Generic: Unicode escape resolution...")
    text, n = unicode_escape_resolution(text)
    details['unicode_escapes'] = n
    if verbose and n:
        print(f"    Resolved {n} Unicode escapes")

    if verbose:
        print("[*] Generic: AES/cipher string annotation...")
    text, n = aes_string_annotation(text)
    details['aes_strings'] = n
    if verbose and n:
        print(f"    Annotated {n} cipher string patterns")

    if verbose:
        print("[*] Generic: String table resolution...")
    text, n = string_table_resolution(text)
    details['string_tables'] = n
    if verbose and n:
        print(f"    Resolved {n} string table accesses")

    if verbose:
        print("[*] Generic: Enhanced reflection annotation...")
    text, n = enhanced_reflection_annotation(text)
    details['enhanced_reflection'] = n
    if verbose and n:
        print(f"    Annotated {n} reflection/exec calls")

    if verbose:
        print("[*] Generic: Il/lI confusable annotation...")
    text, n = il_confusable_annotation(text)
    details['il_confusables'] = n
    if verbose and n:
        print(f"    Detected {n} confusable identifiers")

    if verbose:
        print("[*] Generic: Windows reserved name detection...")
    text, n = windows_reserved_name_detection(text)
    details['reserved_names'] = n
    if verbose and n:
        print(f"    Flagged {n} Windows reserved name usages")

    if verbose:
        print("[*] Generic: Reflection cleanup...")
    text, n = generic_reflection_cleanup(text)
    details['reflection'] = n
    if verbose and n:
        print(f"    Annotated {n} reflection calls")

    if verbose:
        print("[*] Generic: Try-catch cleanup...")
    text, n = generic_try_catch_cleanup(text)
    details['try_catch'] = n
    if verbose and n:
        print(f"    Cleaned {n} try-catch blocks")

    if verbose:
        print("[*] Generic: Try-finally unwrap...")
    text, n = try_finally_unwrap(text)
    details['try_finally'] = n
    if verbose and n:
        print(f"    Unwrapped {n} empty try-finally blocks")

    if verbose:
        print("[*] Generic: Dead code elimination...")
    text, n = generic_dead_code_elimination(text)
    details['generic_dead'] = n
    if verbose and n:
        print(f"    Removed {n} dead code blocks")

    # Pass 11: Cleanup
    if verbose:
        print("\n[*] Pass 11: Final cleanup...")
    text = cleanup_empty_blocks(text)

    # === CONVERGENCE: Re-run generic passes if changes are still happening ===
    MAX_ITERATIONS = 3
    for iteration in range(MAX_ITERATIONS):
        prev_len = len(text)
        text2, n1 = generic_dead_code_elimination(text)
        text2, n2 = mba_simplify(text2)
        text2, n3 = math_opaque_predicate_elimination(text2)
        text2, n4 = bogus_loop_removal(text2)
        total_changes = n1 + n2 + n3 + n4
        if total_changes == 0 or len(text2) >= prev_len:
            break
        text = text2
        text = cleanup_empty_blocks(text)
        if verbose:
            print(f"[*] Convergence pass {iteration + 1}: {total_changes} additional changes")

    # Assess confidence
    confidence = assess_confidence(original, text, details)

    # Generate stats
    stats = generate_stats(original, text, details)

    # Append confidence to stats
    conf = confidence
    conf_bar = '#' * int(conf['confidence'] * 20) + '-' * (20 - int(conf['confidence'] * 20))
    stats += f"""
  Confidence: {conf['confidence']:.0%} [{conf_bar}] {conf['level']}
"""
    if conf['issues']:
        stats += "  Issues:\n"
        for issue in conf['issues']:
            stats += f"    - {issue}\n"
    if conf['recommend_fallback']:
        stats += "\n  >> RECOMMENDATION: Run java-deobfuscator as fallback (--auto-fallback)\n"

    if verbose:
        try:
            print(stats)
        except UnicodeEncodeError:
            print(stats.encode('ascii', errors='replace').decode('ascii'))

    # Write output
    if output_path is None:
        base, ext = os.path.splitext(input_path)
        output_path = f"{base}_deobfuscated{ext}"

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"// {'=' * 60}\n")
        f.write(f"// DEOBFUSCATED by Universal Java Deobfuscator v4.0\n")
        f.write(f"// Original: {os.path.basename(input_path)}\n")
        f.write(f"// Confidence: {conf['confidence']:.0%} ({conf['level']})\n")
        f.write(f"// Techniques handled: ZWC, opaque predicates, junk code,\n")
        f.write(f"//   CFF, XOR constants, wrapper methods, string labeling\n")
        if conf['recommend_fallback']:
            f.write(f"// NOTE: Low confidence — java-deobfuscator fallback recommended\n")
        f.write(f"// {'=' * 60}\n\n")
        f.write(text)

    if verbose:
        print(f"\n[+] Written deobfuscated output to {output_path}")

    return output_path, confidence


# ═══════════════════════════════════════════════════════════════════════
#  OPTION 2: java-deobfuscator integration
# ═══════════════════════════════════════════════════════════════════════

JAVA_DEOBF_JAR_URL = "https://github.com/java-deobfuscator/deobfuscator/releases/latest"
NARUMII_DEOBF_JAR_URL = "https://github.com/narumii/Deobfuscator/releases/latest"


# ═══════════════════════════════════════════════════════════════════════
#  JAR PREPROCESSING — strip Bozar anti-analysis traps
# ═══════════════════════════════════════════════════════════════════════

def strip_bozar_traps(input_jar: str, verbose: bool = False) -> str:
    """Strip Bozar anti-analysis entries from a JAR before processing.

    Bozar injects:
    - BOZAR/ directory tree (1024+ nested empty folders → StackOverflow in tools)
    - NAUGHTY NAUGHTY.class (junk class that crashes some parsers)
    - Extremely long filenames

    Returns path to cleaned JAR (temp copy if changes were made, original if clean).
    """
    import zipfile
    import tempfile

    try:
        with zipfile.ZipFile(input_jar, 'r') as zf:
            entries = zf.namelist()
    except (zipfile.BadZipFile, Exception) as e:
        if verbose:
            print(f"[!] Cannot read JAR: {e}")
        return input_jar

    # Check for Bozar traps
    trap_prefixes = ('BOZAR/', 'BOZAR\\')
    trap_names = ('NAUGHTY NAUGHTY.class', 'NAUGHTY_NAUGHTY.class')
    max_name_len = 200  # Bozar sometimes uses absurdly long filenames

    traps_found = []
    for entry in entries:
        if any(entry.startswith(p) for p in trap_prefixes):
            traps_found.append(entry)
        elif any(entry.endswith(n) for n in trap_names):
            traps_found.append(entry)
        elif len(entry) > max_name_len:
            traps_found.append(entry)

    if not traps_found:
        if verbose:
            print("    No Bozar traps found in JAR")
        return input_jar

    if verbose:
        print(f"    Found {len(traps_found)} Bozar trap entries — stripping...")

    # Create cleaned copy
    trap_set = set(traps_found)
    base, ext = os.path.splitext(input_jar)
    cleaned_jar = f"{base}_cleaned{ext}"

    try:
        with zipfile.ZipFile(input_jar, 'r') as zf_in:
            with zipfile.ZipFile(cleaned_jar, 'w', zipfile.ZIP_DEFLATED) as zf_out:
                MAX_ENTRY_SIZE = 100 * 1024 * 1024  # 100 MB per entry
                for entry in entries:
                    if entry not in trap_set:
                        info = zf_in.getinfo(entry)
                        if info.file_size > MAX_ENTRY_SIZE:
                            if verbose:
                                print(f"    Skipping oversized entry: {entry} ({info.file_size} bytes)")
                            continue
                        zf_out.writestr(entry, zf_in.read(entry))

        if verbose:
            kept = len(entries) - len(traps_found)
            print(f"    Stripped {len(traps_found)} traps, kept {kept} entries -> {cleaned_jar}")

        return cleaned_jar
    except Exception as e:
        if verbose:
            print(f"[!] Failed to strip traps: {e}")
        return input_jar


# ═══════════════════════════════════════════════════════════════════════
#  FALLBACK 1: java-deobfuscator
# ═══════════════════════════════════════════════════════════════════════

def _find_tool_jar(name: str, search_names: list[str]) -> Optional[str]:
    """Search for a tool JAR in standard locations."""
    search_dirs = [
        os.path.join(os.path.dirname(__file__), '..', 'tools'),
        os.path.join(os.path.dirname(__file__), 'tools'),
        '.',
        'tools',
    ]
    for d in search_dirs:
        for sn in search_names:
            p = os.path.join(d, sn)
            if os.path.exists(p):
                return os.path.abspath(p)
    return None


def run_java_deobfuscator(input_jar: str, output_jar: Optional[str] = None,
                          java_deobf_jar: Optional[str] = None,
                          transformers: Optional[list[str]] = None,
                          verbose: bool = False) -> Optional[str]:
    """Run java-deobfuscator on a JAR file.

    Automatically strips Bozar directory traps before processing
    (java-deobfuscator crashes on the nested BOZAR/ folder bomb).

    Returns output JAR path on success, None on failure.
    """
    if output_jar is None:
        base, ext = os.path.splitext(input_jar)
        output_jar = f"{base}_jdeobf{ext}"

    # Auto-detect java-deobfuscator JAR
    if java_deobf_jar is None:
        java_deobf_jar = _find_tool_jar(
            'java-deobfuscator',
            ['deobfuscator.jar', 'java-deobfuscator.jar']
        )

    if java_deobf_jar is None or not os.path.exists(java_deobf_jar):
        if verbose:
            print(f"[!] java-deobfuscator JAR not found.")
            print(f"    Download from: {JAVA_DEOBF_JAR_URL}")
            print(f"    Place it at: tools/deobfuscator.jar")
        return None

    # Strip Bozar traps first
    if verbose:
        print("[*] Checking for Bozar anti-analysis traps...")
    clean_jar = strip_bozar_traps(input_jar, verbose)

    # Default Bozar-appropriate transformers
    if transformers is None:
        transformers = [
            "com.javadeobfuscator.deobfuscator.transformers.general.removers.SyntheticBridgeRemover",
            "com.javadeobfuscator.deobfuscator.transformers.normalizer.MethodNormalizer",
            "com.javadeobfuscator.deobfuscator.transformers.normalizer.FieldNormalizer",
            "com.javadeobfuscator.deobfuscator.transformers.normalizer.ClassNormalizer",
            "com.javadeobfuscator.deobfuscator.transformers.general.peephole.PeepholeOptimizer",
            "com.javadeobfuscator.deobfuscator.transformers.stringer.StringEncryptionTransformer",
        ]

    # Check for java
    java_cmd = shutil.which('java')
    if java_cmd is None:
        if verbose:
            print("[!] Java not found in PATH. java-deobfuscator requires Java 8+.")
        return None

    # Build command
    cmd = [java_cmd, '-jar', java_deobf_jar, '-input', clean_jar, '-output', output_jar]
    for t in transformers:
        cmd.extend(['-transformer', t])

    if verbose:
        print(f"[*] Running java-deobfuscator...")
        print(f"    Input:  {clean_jar}")
        print(f"    Output: {output_jar}")
        print(f"    Transformers: {len(transformers)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if verbose:
            if result.stdout:
                # Show last chunk of output
                print(result.stdout[-1000:])
            if result.returncode != 0:
                print(f"[!] java-deobfuscator exited with code {result.returncode}")
                if result.stderr:
                    print(result.stderr[-500:])
                return None
        if verbose:
            print(f"[+] java-deobfuscator output: {output_jar}")
        return output_jar
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] java-deobfuscator timed out (300s)")
        return None
    except FileNotFoundError:
        if verbose:
            print(f"[!] Could not execute: {' '.join(cmd[:3])}")
        return None


# ═══════════════════════════════════════════════════════════════════════
#  FALLBACK 2: narumii/Deobfuscator (Bozar-specific bytecode transforms)
# ═══════════════════════════════════════════════════════════════════════

def run_narumii_deobfuscator(input_jar: str, output_jar: Optional[str] = None,
                             narumii_jar: Optional[str] = None,
                             verbose: bool = False) -> Optional[str]:
    """Run narumii/Deobfuscator which has Bozar-specific transforms.

    This is the best bytecode-level tool for Bozar because it has
    dedicated transformers for Bozar's specific obfuscation patterns.
    Requires Java 17 + Java 8 sandbox.

    Returns output JAR path on success, None on failure.
    """
    if output_jar is None:
        base, ext = os.path.splitext(input_jar)
        output_jar = f"{base}_narumii{ext}"

    # Auto-detect narumii JAR
    if narumii_jar is None:
        narumii_jar = _find_tool_jar(
            'narumii-deobfuscator',
            ['narumii-deobfuscator.jar', 'narumii.jar', 'Deobfuscator.jar']
        )

    if narumii_jar is None or not os.path.exists(narumii_jar):
        if verbose:
            print(f"[!] narumii/Deobfuscator JAR not found.")
            print(f"    Download from: {NARUMII_DEOBF_JAR_URL}")
            print(f"    Place it at: tools/narumii-deobfuscator.jar")
        return None

    # Strip Bozar traps first
    if verbose:
        print("[*] Checking for Bozar anti-analysis traps...")
    clean_jar = strip_bozar_traps(input_jar, verbose)

    java_cmd = shutil.which('java')
    if java_cmd is None:
        if verbose:
            print("[!] Java not found in PATH.")
        return None

    # narumii uses a config-based approach, but also supports CLI
    # Try CLI mode first: java -jar Deobfuscator.jar -input X -output Y -transformer bozar
    cmd = [java_cmd, '-jar', narumii_jar, '-input', clean_jar, '-output', output_jar]

    if verbose:
        print(f"[*] Running narumii/Deobfuscator (Bozar-specific)...")
        print(f"    Input:  {clean_jar}")
        print(f"    Output: {output_jar}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if verbose:
            if result.stdout:
                print(result.stdout[-1000:])
            if result.returncode != 0:
                print(f"[!] narumii/Deobfuscator exited with code {result.returncode}")
                if result.stderr:
                    print(result.stderr[-500:])
                return None
        if verbose:
            print(f"[+] narumii/Deobfuscator output: {output_jar}")
        return output_jar
    except subprocess.TimeoutExpired:
        if verbose:
            print("[!] narumii/Deobfuscator timed out (300s)")
        return None
    except FileNotFoundError:
        if verbose:
            print(f"[!] Could not execute: {' '.join(cmd[:3])}")
        return None


# ═══════════════════════════════════════════════════════════════════════
#  FALLBACK CHAIN — tries each tool in order until one succeeds
# ═══════════════════════════════════════════════════════════════════════

def run_fallback_chain(input_jar: str, java_deobf_jar: Optional[str] = None,
                       narumii_jar: Optional[str] = None,
                       transformers: Optional[list[str]] = None,
                       verbose: bool = False) -> Optional[str]:
    """Try multiple deobfuscation tools in order of Bozar-specificity.

    Chain: narumii (Bozar-specific) -> java-deobfuscator (generic) -> None

    Returns the first successful output path, or None if all fail.
    """
    if verbose:
        print("\n[*] === FALLBACK CHAIN ===")

    # Fallback 1: narumii/Deobfuscator (best for Bozar)
    if verbose:
        print("\n[*] Fallback 1: narumii/Deobfuscator (Bozar-specific)...")
    result = run_narumii_deobfuscator(input_jar, narumii_jar=narumii_jar, verbose=verbose)
    if result:
        return result

    # Fallback 2: java-deobfuscator (generic, with Bozar trap stripping)
    if verbose:
        print("\n[*] Fallback 2: java-deobfuscator (generic)...")
    result = run_java_deobfuscator(
        input_jar, java_deobf_jar=java_deobf_jar,
        transformers=transformers, verbose=verbose
    )
    if result:
        return result

    if verbose:
        print("\n[!] All fallback tools unavailable or failed.")
        print("    To enable fallbacks, download and place in tools/:")
        print(f"    1. narumii/Deobfuscator: {NARUMII_DEOBF_JAR_URL}")
        print(f"       -> tools/narumii-deobfuscator.jar")
        print(f"    2. java-deobfuscator:    {JAVA_DEOBF_JAR_URL}")
        print(f"       -> tools/deobfuscator.jar")

    return None


# ═══════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Universal Java Deobfuscator v4.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  Default: Custom deobfuscation with auto-fallback chain
    python deobfuscator.py message_14.txt -v
    python deobfuscator.py malware.jar -v

  Force bytecode tools only (skip custom):
    python deobfuscator.py --java-deobf-only malware.jar -v

  Force custom only (no fallback):
    python deobfuscator.py --no-fallback message_14.txt -v

  Force all tools regardless of confidence:
    python deobfuscator.py --both malware.jar -v

Auto-fallback chain (when confidence < 75%%):
  1. narumii/Deobfuscator - Bozar-specific bytecode transforms (best)
  2. java-deobfuscator    - generic transforms with peephole optimizer
  Both tools auto-strip Bozar's BOZAR/ directory bomb before processing.

Required tool JARs (place in tools/ directory):
  tools/narumii-deobfuscator.jar  - from github.com/narumii/Deobfuscator
  tools/deobfuscator.jar          - from github.com/java-deobfuscator/deobfuscator
        """
    )
    parser.add_argument('input', help='Path to obfuscated file (.java/.txt or .jar)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show progress and statistics')
    parser.add_argument('--java-deobf-only', action='store_true',
                        help='Only run java-deobfuscator (skip custom deobfuscation)')
    parser.add_argument('--java-deobf-jar', help='Path to java-deobfuscator JAR')
    parser.add_argument('--no-fallback', action='store_true',
                        help='Disable auto-fallback to java-deobfuscator')
    parser.add_argument('--both', action='store_true',
                        help='Run both custom and java-deobfuscator regardless of confidence')
    parser.add_argument('--transformers', nargs='*', help='java-deobfuscator transformers')

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: File not found: {args.input}")
        sys.exit(1)

    is_jar = args.input.lower().endswith('.jar')

    # --- Mode: java-deobfuscator only ---
    if args.java_deobf_only:
        if not is_jar:
            print("[!] --java-deobf-only requires a .jar input file")
            sys.exit(1)
        out = run_java_deobfuscator(
            args.input, args.output, args.java_deobf_jar,
            args.transformers, args.verbose
        )
        if out:
            print(f"java-deobfuscator output: {out}")
        return

    # --- Mode: force both ---
    if args.both:
        output, confidence = deobfuscate(args.input, args.output, args.verbose)
        print(f"Custom deobfuscation: {output} (confidence: {confidence['confidence']:.0%})")
        if is_jar:
            fallback_out = run_fallback_chain(
                args.input,
                java_deobf_jar=args.java_deobf_jar,
                transformers=args.transformers,
                verbose=args.verbose
            )
            if fallback_out:
                print(f"Fallback chain output: {fallback_out}")
        return

    # --- Default mode: custom with auto-fallback ---
    output, confidence = deobfuscate(args.input, args.output, args.verbose)
    print(f"Deobfuscated: {output} (confidence: {confidence['confidence']:.0%} {confidence['level']})")

    # Auto-fallback check
    if confidence['recommend_fallback'] and not args.no_fallback:
        print()
        print(f"[!] Confidence is {confidence['confidence']:.0%} ({confidence['level']}) — triggering fallback chain")
        if confidence['issues']:
            for issue in confidence['issues']:
                print(f"    - {issue}")

        if is_jar:
            fallback_out = run_fallback_chain(
                args.input,
                java_deobf_jar=args.java_deobf_jar,
                transformers=args.transformers,
                verbose=args.verbose
            )
            if fallback_out:
                print(f"\n[+] Fallback output: {fallback_out}")
                print(f"    Compare with custom output for best results: {output}")
        else:
            # Source file — bytecode tools need a .jar
            print()
            print("[*] Input is a source file — bytecode fallbacks require a .jar.")
            print("    To improve results:")
            print("    1. Obtain the full JAR and run: python deobfuscator.py malware.jar -v")
            print("    2. narumii/Deobfuscator has Bozar-specific bytecode transforms")
            print("    3. java-deobfuscator can handle generic obfuscation patterns")
            print(f"    Place tools in: tools/narumii-deobfuscator.jar, tools/deobfuscator.jar")


if __name__ == '__main__':
    main()
