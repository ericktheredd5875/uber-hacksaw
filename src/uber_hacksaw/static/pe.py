"""PE File sanalysis utilities."""

from __future__ import annotations

from typing import Any

import pefile
from loguru import logger


def analyze_pe(data: bytes) -> dict[str, Any]:
    """Analyze PE file structure and extract metadata."""
    result = {
        "is_pe": False,
        "imports": [],
        "sections": [],
        "entropy": 0.0,
        "suspicious_apis": [],
        "is_packed": False,
    }

    try:
        pe = pefile.PE(data=data)
        result["is_pe"] = True

        # Extract Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="ignore")
                        result["imports"].append(f"{dll_name}.{api_name}")

        # Extract Section Information
        for section in pe.sections:
            section_info = {
                "name": section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy(),
            }
            result["sections"].append(section_info)

        # Calculate overall Entropy
        if result["sections"]:
            result["entropy"] = sum(s["entropy"] for s in result["sections"]) / len(
                result["sections"]
            )

        # Check for suspicious APIs
        suspicious_apis = {
            "kernel32.CreateProcess",
            "kernel32.CreateProcessA",
            "kernel32.CreateProcessW",
            "kernel32.VirtualAlloc",
            "kernel32.VirtualAllocEx",
            "kernel32.WriteProcessMemory",
            "kernel32.ReadProcessMemory",
            "kernel32.OpenProcess",
            "kernel32.TerminateProcess",
            "advapi32.RegOpenKey",
            "advapi32.RegSetValue",
            "wininet.InternetOpen",
            "wininet.InternetConnect",
            "ws2_32.WSAStartup",
            "ws2_32.socket",
            "ws2_32.connect",
        }

        result["suspicious_apis"] = [api for api in result["imports"] if api in suspicious_apis]

        # Check for packing indicators
        if result["entropy"] > 7.0:  # High entropy suggests packing
            result["is_packed"] = True

        pe.close()

    except Exception as e:
        logger.debug(f"PE analysis failed: {e}")

    return result
