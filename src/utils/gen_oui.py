#!/usr/bin/env python3
"""Generate oui_data.cpp from oui.txt and nmap-mac-prefixes."""

import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUI_FILE = os.path.join(SCRIPT_DIR, "oui.txt")
NMAP_FILE = os.path.join(SCRIPT_DIR, "nmap-mac-prefixes")
OUTPUT = os.path.join(SCRIPT_DIR, "oui_data.cpp")

entries = {}  # prefix -> vendor

# Parse IEEE oui.txt: "XX-XX-XX   (hex)    VENDOR"
if os.path.exists(OUI_FILE):
    with open(OUI_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "(hex)" not in line:
                continue
            # Format: "00-00-00   (hex)    Vendor Name"
            try:
                prefix = line[:8].strip().replace("-", "").upper()
                vendor = line[18:].strip()
                if len(prefix) == 6 and vendor and "(base 16)" not in vendor:
                    entries[prefix] = vendor
            except:
                pass

# Parse nmap-mac-prefixes: "XXXXXX\tVENDOR"
if os.path.exists(NMAP_FILE):
    with open(NMAP_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                prefix, vendor = line.split("\t", 1)
                prefix = prefix.strip().upper()
                vendor = vendor.strip()
                if len(prefix) == 6 and vendor:
                    entries[prefix] = vendor

# Sort by prefix
sorted_entries = sorted(entries.items())

# Generate C++ source
with open(OUTPUT, "w", encoding="utf-8") as out:
    out.write("// Auto-generated from oui.txt + nmap-mac-prefixes\n")
    out.write(f"// Total entries: {len(sorted_entries)}\n")
    out.write('#include "OuiLookup.hpp"\n')
    out.write("#include <cstring>\n")
    out.write("#include <cstdint>\n\n")

    out.write("struct OuiEntry {\n")
    out.write("    uint32_t prefix;   // 3 bytes, 0x000000..0xFFFFFF\n")
    out.write('    const char* vendor;\n')
    out.write("};\n\n")

    out.write(f"static const OuiEntry s_ouiTable[{len(sorted_entries)}] = {{\n")
    for prefix, vendor in sorted_entries:
        p = int(prefix, 16)
        # Escape backslash, double-quote, and control chars in vendor name
        escaped = vendor.replace("\\", "\\\\").replace('"', '\\"')
        # Remove any non-ASCII chars that would break compilation
        escaped = ''.join(c if ord(c) >= 32 and ord(c) < 127 else '?' for c in escaped)
        out.write(f"    {{ 0x{p:06X}, \"{escaped}\" }},\n")
    out.write("};\n\n")

    out.write("std::string ouiLookup(const uint8_t bssid[6]) {\n")
    out.write("    uint32_t prefix = ((uint32_t)bssid[0] << 16) | ((uint32_t)bssid[1] << 8) | bssid[2];\n\n")
    out.write("    // Binary search\n")
    out.write("    int lo = 0, hi = (int)(sizeof(s_ouiTable) / sizeof(s_ouiTable[0])) - 1;\n")
    out.write("    while (lo <= hi) {\n")
    out.write("        int mid = lo + (hi - lo) / 2;\n")
    out.write("        if (s_ouiTable[mid].prefix == prefix)\n")
    out.write("            return s_ouiTable[mid].vendor;\n")
    out.write("        else if (s_ouiTable[mid].prefix < prefix)\n")
    out.write("            lo = mid + 1;\n")
    out.write("        else\n")
    out.write("            hi = mid - 1;\n")
    out.write("    }\n")
    out.write("    return {};\n")
    out.write("}\n")

print(f"Generated {OUTPUT} with {len(sorted_entries)} entries")
