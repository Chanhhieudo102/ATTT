"""Read-only Windows scan for private executable memory outside loaded modules."""
from __future__ import annotations

import ctypes
import os

DWORD = ctypes.c_uint32
WORD = ctypes.c_uint16
SIZE_T = ctypes.c_size_t
HANDLE = ctypes.c_void_p
HMODULE = ctypes.c_void_p

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
EXECUTABLE_PROTECTIONS = {0x10, 0x20, 0x40, 0x80}
MAX_REGION_QUERIES = 500_000


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", DWORD),
        ("PartitionId", WORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


def _windows_error() -> str:
    error_code = ctypes.get_last_error()
    return ctypes.FormatError(error_code).strip() if error_code else "Windows API call failed"


def _loaded_module_ranges(handle, psapi) -> tuple[list[tuple[int, int]], int, str]:
    enum_modules = psapi.EnumProcessModulesEx
    enum_modules.argtypes = [HANDLE, ctypes.POINTER(HMODULE), DWORD,
                             ctypes.POINTER(DWORD), DWORD]
    enum_modules.restype = ctypes.c_int
    get_module_info = psapi.GetModuleInformation
    get_module_info.argtypes = [HANDLE, HMODULE, ctypes.POINTER(MODULEINFO), DWORD]
    get_module_info.restype = ctypes.c_int

    capacity = 256
    modules = (HMODULE * capacity)()
    needed = DWORD()
    if not enum_modules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), LIST_MODULES_ALL):
        return [], 0, _windows_error()
    if needed.value > ctypes.sizeof(modules):
        capacity = min(needed.value // ctypes.sizeof(HMODULE) + 32, 65_536)
        modules = (HMODULE * capacity)()
        if not enum_modules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), LIST_MODULES_ALL):
            return [], 0, _windows_error()

    count = min(needed.value // ctypes.sizeof(HMODULE), capacity)
    ranges = []
    failures = 0
    for module in modules[:count]:
        info = MODULEINFO()
        if not get_module_info(handle, module, ctypes.byref(info), ctypes.sizeof(info)):
            failures += 1
            continue
        base = int(info.lpBaseOfDll or 0)
        size = int(info.SizeOfImage or 0)
        if base and size:
            ranges.append((base, base + size))
    if not ranges:
        return [], 0, "Không lấy được danh sách module của tiến trình"
    note = f"Không đọc được thông tin của {failures} module" if failures else "OK"
    return ranges, len(ranges), note


def inspect_private_executable_regions(pid: int) -> dict:
    """Compare committed executable MEM_PRIVATE regions with enumerated modules.

    The function opens the target for query/read access only and never reads or
    writes the region contents. Private executable memory can be legitimate
    (for example JIT runtimes); results are triage indicators, not proof of
    process injection.
    """
    if os.name != "nt":
        return {"status": "Chỉ hỗ trợ trên Windows", "module_count": 0,
                "region_count": 0, "unbacked_executable_region_count": 0, "samples": []}
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return {"status": "PID không hợp lệ", "module_count": 0,
                "region_count": 0, "unbacked_executable_region_count": 0, "samples": []}
    if pid <= 0:
        return {"status": "PID phải là số dương", "module_count": 0,
                "region_count": 0, "unbacked_executable_region_count": 0, "samples": []}

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [DWORD, ctypes.c_int, DWORD]
    open_process.restype = HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [HANDLE]
    close_handle.restype = ctypes.c_int
    query = kernel32.VirtualQueryEx
    query.argtypes = [HANDLE, ctypes.c_void_p,
                      ctypes.POINTER(MEMORY_BASIC_INFORMATION), SIZE_T]
    query.restype = SIZE_T
    get_system_info = kernel32.GetSystemInfo
    get_system_info.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
    get_system_info.restype = None

    handle = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return {"status": f"Không mở được tiến trình: {_windows_error()}", "module_count": 0,
                "region_count": 0, "unbacked_executable_region_count": 0, "samples": []}
    try:
        module_ranges, module_count, module_status = _loaded_module_ranges(handle, psapi)
        if not module_ranges:
            return {"status": module_status, "module_count": module_count,
                    "region_count": 0, "unbacked_executable_region_count": 0, "samples": []}

        system_info = SYSTEM_INFO()
        get_system_info(ctypes.byref(system_info))
        cursor = int(system_info.lpMinimumApplicationAddress or 0)
        maximum = int(system_info.lpMaximumApplicationAddress or 0)
        mbi = MEMORY_BASIC_INFORMATION()
        scanned = 0
        findings = []
        while cursor < maximum and scanned < MAX_REGION_QUERIES:
            returned = query(handle, ctypes.c_void_p(cursor), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not returned:
                # VirtualQueryEx can stop at the maximum user address; a failure
                # before any region is a real query error worth reporting.
                if scanned == 0:
                    return {"status": f"VirtualQueryEx failed: {_windows_error()}",
                            "module_count": module_count, "region_count": 0,
                            "unbacked_executable_region_count": 0, "samples": []}
                break
            scanned += 1
            base = int(mbi.BaseAddress or 0)
            allocation_base = int(mbi.AllocationBase or 0)
            size = int(mbi.RegionSize or 0)
            if size <= 0 or base + size <= cursor:
                break
            base_protection = int(mbi.Protect) & 0xFF
            executable = (base_protection in EXECUTABLE_PROTECTIONS
                          and not (int(mbi.Protect) & (PAGE_GUARD | PAGE_NOACCESS)))
            if (int(mbi.State) == MEM_COMMIT and int(mbi.Type) == MEM_PRIVATE
                    and executable and allocation_base):
                belongs_to_module = any(start <= allocation_base < end
                                        for start, end in module_ranges)
                if not belongs_to_module:
                    findings.append({"base": f"0x{base:X}",
                                     "allocation_base": f"0x{allocation_base:X}",
                                     "size_bytes": size,
                                     "protect": f"0x{int(mbi.Protect):X}"})
            cursor = base + size

        status = module_status
        if scanned >= MAX_REGION_QUERIES:
            status = "Giới hạn số vùng quét đạt tới; kết quả có thể chưa đầy đủ"
        return {"status": status, "module_count": module_count,
                "region_count": scanned,
                "unbacked_executable_region_count": len(findings),
                "samples": findings[:12]}
    finally:
        close_handle(handle)
