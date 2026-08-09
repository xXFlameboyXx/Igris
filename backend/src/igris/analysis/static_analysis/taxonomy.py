"""Static-analysis string and API taxonomy."""

import ipaddress
import re

from igris.schemas.static_analysis import ImportCategory, StringCategory

URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
DOMAIN_RE = re.compile(r"(?i)\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b")
WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\[^\s\"'<>|]+")
UNIX_PATH_RE = re.compile(r"(?:^|\s)(/[A-Za-z0-9._/\-]+)")
REGISTRY_RE = re.compile(r"(?i)\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"']+")

COMMAND_INDICATORS = {
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "/bin/sh",
    "/bin/bash",
}

SUSPICIOUS_KEYWORDS = {
    "credential",
    "keylogger",
    "mimikatz",
    "persistence",
    "privilege",
    "shellcode",
    "inject",
    "download",
    "autorun",
    "disable",
}

API_TAXONOMY: dict[str, ImportCategory] = {
    "CreateProcessA": ImportCategory.PROCESS_MANAGEMENT,
    "CreateProcessW": ImportCategory.PROCESS_MANAGEMENT,
    "OpenProcess": ImportCategory.PROCESS_MANAGEMENT,
    "TerminateProcess": ImportCategory.PROCESS_MANAGEMENT,
    "VirtualAlloc": ImportCategory.MEMORY_MANAGEMENT,
    "VirtualAllocEx": ImportCategory.MEMORY_MANAGEMENT,
    "VirtualProtect": ImportCategory.MEMORY_MANAGEMENT,
    "VirtualProtectEx": ImportCategory.MEMORY_MANAGEMENT,
    "WriteProcessMemory": ImportCategory.PROCESS_THREAD_MANIPULATION,
    "ReadProcessMemory": ImportCategory.PROCESS_THREAD_MANIPULATION,
    "CreateRemoteThread": ImportCategory.PROCESS_THREAD_MANIPULATION,
    "CreateThread": ImportCategory.PROCESS_THREAD_MANIPULATION,
    "CreateFileA": ImportCategory.FILESYSTEM,
    "CreateFileW": ImportCategory.FILESYSTEM,
    "WriteFile": ImportCategory.FILESYSTEM,
    "ReadFile": ImportCategory.FILESYSTEM,
    "DeleteFileA": ImportCategory.FILESYSTEM,
    "DeleteFileW": ImportCategory.FILESYSTEM,
    "RegOpenKeyExA": ImportCategory.REGISTRY,
    "RegOpenKeyExW": ImportCategory.REGISTRY,
    "RegSetValueExA": ImportCategory.REGISTRY,
    "RegSetValueExW": ImportCategory.REGISTRY,
    "InternetOpenA": ImportCategory.NETWORKING,
    "InternetOpenW": ImportCategory.NETWORKING,
    "InternetConnectA": ImportCategory.NETWORKING,
    "InternetConnectW": ImportCategory.NETWORKING,
    "HttpSendRequestA": ImportCategory.NETWORKING,
    "HttpSendRequestW": ImportCategory.NETWORKING,
    "WSAStartup": ImportCategory.NETWORKING,
    "connect": ImportCategory.NETWORKING,
    "send": ImportCategory.NETWORKING,
    "recv": ImportCategory.NETWORKING,
    "CryptAcquireContextA": ImportCategory.CRYPTOGRAPHY,
    "CryptAcquireContextW": ImportCategory.CRYPTOGRAPHY,
    "CryptEncrypt": ImportCategory.CRYPTOGRAPHY,
    "CryptDecrypt": ImportCategory.CRYPTOGRAPHY,
    "BCryptEncrypt": ImportCategory.CRYPTOGRAPHY,
    "OpenSCManagerA": ImportCategory.SERVICE_MANAGEMENT,
    "OpenSCManagerW": ImportCategory.SERVICE_MANAGEMENT,
    "CreateServiceA": ImportCategory.SERVICE_MANAGEMENT,
    "CreateServiceW": ImportCategory.SERVICE_MANAGEMENT,
    "StartServiceA": ImportCategory.SERVICE_MANAGEMENT,
    "StartServiceW": ImportCategory.SERVICE_MANAGEMENT,
    "GetComputerNameA": ImportCategory.SYSTEM_INFORMATION,
    "GetComputerNameW": ImportCategory.SYSTEM_INFORMATION,
    "GetUserNameA": ImportCategory.SYSTEM_INFORMATION,
    "GetUserNameW": ImportCategory.SYSTEM_INFORMATION,
    "IsDebuggerPresent": ImportCategory.SYSTEM_INFORMATION,
}


def classify_string(value: str) -> StringCategory:
    stripped = value.strip()
    lowered = stripped.lower()

    if URL_RE.search(stripped):
        return StringCategory.URL
    if EMAIL_RE.search(stripped):
        return StringCategory.EMAIL
    if REGISTRY_RE.search(stripped):
        return StringCategory.REGISTRY_PATH
    if WINDOWS_PATH_RE.search(stripped):
        return StringCategory.WINDOWS_PATH
    if UNIX_PATH_RE.search(stripped):
        return StringCategory.UNIX_PATH
    if lowered in COMMAND_INDICATORS or any(command in lowered for command in COMMAND_INDICATORS):
        return StringCategory.COMMAND_INTERPRETER
    if _is_ip_address(stripped, version=4):
        return StringCategory.IPV4
    if _is_ip_address(stripped, version=6):
        return StringCategory.IPV6
    if DOMAIN_RE.search(stripped):
        return StringCategory.DOMAIN
    if any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS):
        return StringCategory.SUSPICIOUS_KEYWORD
    return StringCategory.GENERIC


def categorize_api(name: str) -> ImportCategory:
    return API_TAXONOMY.get(name, ImportCategory.OTHER)


def is_interesting_string(category: StringCategory) -> bool:
    return category != StringCategory.GENERIC


def _is_ip_address(value: str, *, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False
