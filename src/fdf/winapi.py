"""
winapi.py — FDF 强制删除工具的 Win32 / NT Native API 绑定层（纯 ctypes，无第三方依赖）

参考的开源实现思路：
  * zerx-lab/rmx            —— POSIX 语义删除 (FileDispositionInfoEx)、
                                NtQuerySystemInformation + DuplicateHandle(DUPLICATE_CLOSE_SOURCE) 强关句柄
  * cklutz/LockCheck        —— NtQueryInformationFile(FileProcessIdsUsingFileInformation) 精准查占用进程
  * microsoft/PowerToys     —— Restart Manager (RmStartSession/RmGetList) 列出锁定进程
"""

import ctypes
import os
from ctypes import wintypes

# ---------------------------------------------------------------- DLL 句柄
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
try:
    rstrtmgr = ctypes.WinDLL("rstrtmgr", use_last_error=True)
except OSError:  # 极老系统上可能缺失
    rstrtmgr = None

# ---------------------------------------------------------------- 常量
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000
FILE_READ_ATTRIBUTES = 0x0080
FILE_ALL_ACCESS = 0x001F01FF

FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4
FILE_SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_WRITE_THROUGH = 0x80000000

FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
MOVEFILE_REPLACE_EXISTING = 0x1

# FILE_INFO_BY_HANDLE_CLASS
FileDispositionInfo = 4
FileDispositionInfoEx = 21

FILE_DISPOSITION_FLAG_DELETE = 0x01
FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x02
FILE_DISPOSITION_FLAG_FORCE_IMAGE_SECTION_CHECK = 0x04
FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE = 0x10

# NT 状态 / 信息类
STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004 - (1 << 32)  # 有符号表示
FileProcessIdsUsingFileInformation = 47
SystemHandleInformation = 0x10
SystemExtendedHandleInformation = 0x40

# 进程访问权限
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_DUP_HANDLE = 0x0040

DUPLICATE_CLOSE_SOURCE = 0x1
DUPLICATE_SAME_ACCESS = 0x2

FILE_TYPE_DISK = 0x0001
FILE_NAME_NORMALIZED = 0x0

# 常见错误码
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33
ERROR_DIR_NOT_EMPTY = 145
ERROR_MORE_DATA = 234

# 安全相关
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ACL_REVISION = 2
CONTAINER_INHERIT_ACE = 0x2
OBJECT_INHERIT_ACE = 0x1

TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x00000002
TokenUser = 1

ULONG_PTR = ctypes.c_size_t
LPVOID = ctypes.c_void_p
NTSTATUS = ctypes.c_long


# ---------------------------------------------------------------- 结构体
class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class WIN32_FIND_DATAW(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime", FILETIME),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("dwReserved0", wintypes.DWORD),
        ("dwReserved1", wintypes.DWORD),
        ("cFileName", wintypes.WCHAR * 260),
        ("cAlternateFileName", wintypes.WCHAR * 14),
    ]


class FILE_DISPOSITION_INFO_EX(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD)]


class _IOSB_UNION(ctypes.Union):
    _fields_ = [("Status", NTSTATUS), ("Pointer", LPVOID)]


class IO_STATUS_BLOCK(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("u", _IOSB_UNION), ("Information", ULONG_PTR)]


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", LPVOID),
        ("UniqueProcessId", ULONG_PTR),
        ("HandleValue", ULONG_PTR),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", LPVOID), ("Attributes", wintypes.DWORD)]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63
CCH_RM_SESSION_KEY = 32


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", FILETIME)]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", ctypes.c_int),
        ("AppStatus", wintypes.ULONG),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]


# ---------------------------------------------------------------- 函数原型
def _proto(dll, name, restype, argtypes):
    fn = getattr(dll, name)
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


CreateFileW = _proto(kernel32, "CreateFileW", wintypes.HANDLE,
                     [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, LPVOID,
                      wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE])
CloseHandle = _proto(kernel32, "CloseHandle", wintypes.BOOL, [wintypes.HANDLE])
DeleteFileW = _proto(kernel32, "DeleteFileW", wintypes.BOOL, [wintypes.LPCWSTR])
RemoveDirectoryW = _proto(kernel32, "RemoveDirectoryW", wintypes.BOOL, [wintypes.LPCWSTR])
GetFileAttributesW = _proto(kernel32, "GetFileAttributesW", wintypes.DWORD, [wintypes.LPCWSTR])
SetFileAttributesW = _proto(kernel32, "SetFileAttributesW", wintypes.BOOL,
                            [wintypes.LPCWSTR, wintypes.DWORD])
MoveFileExW = _proto(kernel32, "MoveFileExW", wintypes.BOOL,
                     [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD])
SetFileInformationByHandle = _proto(kernel32, "SetFileInformationByHandle", wintypes.BOOL,
                                    [wintypes.HANDLE, ctypes.c_int, LPVOID, wintypes.DWORD])
FindFirstFileExW = _proto(kernel32, "FindFirstFileExW", wintypes.HANDLE,
                          [wintypes.LPCWSTR, ctypes.c_int, LPVOID, ctypes.c_int,
                           LPVOID, wintypes.DWORD])
FindNextFileW = _proto(kernel32, "FindNextFileW", wintypes.BOOL,
                       [wintypes.HANDLE, ctypes.POINTER(WIN32_FIND_DATAW)])
FindClose = _proto(kernel32, "FindClose", wintypes.BOOL, [wintypes.HANDLE])
GetCurrentProcess = _proto(kernel32, "GetCurrentProcess", wintypes.HANDLE, [])
GetCurrentProcessId = _proto(kernel32, "GetCurrentProcessId", wintypes.DWORD, [])
OpenProcess = _proto(kernel32, "OpenProcess", wintypes.HANDLE,
                     [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD])
TerminateProcess = _proto(kernel32, "TerminateProcess", wintypes.BOOL,
                          [wintypes.HANDLE, wintypes.UINT])
DuplicateHandle = _proto(kernel32, "DuplicateHandle", wintypes.BOOL,
                         [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                          ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                          wintypes.BOOL, wintypes.DWORD])
GetFileType = _proto(kernel32, "GetFileType", wintypes.DWORD, [wintypes.HANDLE])
GetFinalPathNameByHandleW = _proto(kernel32, "GetFinalPathNameByHandleW", wintypes.DWORD,
                                   [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD])
QueryFullProcessImageNameW = _proto(kernel32, "QueryFullProcessImageNameW", wintypes.BOOL,
                                    [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                     ctypes.POINTER(wintypes.DWORD)])
GetLongPathNameW = _proto(kernel32, "GetLongPathNameW", wintypes.DWORD,
                          [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD])
WriteFile = _proto(kernel32, "WriteFile", wintypes.BOOL,
                   [wintypes.HANDLE, LPVOID, wintypes.DWORD,
                    ctypes.POINTER(wintypes.DWORD), LPVOID])
SetFilePointerEx = _proto(kernel32, "SetFilePointerEx", wintypes.BOOL,
                          [wintypes.HANDLE, ctypes.c_longlong,
                           ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD])
GetFileSizeEx = _proto(kernel32, "GetFileSizeEx", wintypes.BOOL,
                       [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)])
FlushFileBuffers = _proto(kernel32, "FlushFileBuffers", wintypes.BOOL, [wintypes.HANDLE])

NtQuerySystemInformation = _proto(ntdll, "NtQuerySystemInformation", NTSTATUS,
                                  [ctypes.c_int, LPVOID, wintypes.ULONG,
                                   ctypes.POINTER(wintypes.ULONG)])
NtQueryInformationFile = _proto(ntdll, "NtQueryInformationFile", NTSTATUS,
                                [wintypes.HANDLE, ctypes.POINTER(IO_STATUS_BLOCK),
                                 LPVOID, wintypes.ULONG, ctypes.c_int])
RtlNtStatusToDosError = _proto(ntdll, "RtlNtStatusToDosError", wintypes.ULONG, [NTSTATUS])

OpenProcessToken = _proto(advapi32, "OpenProcessToken", wintypes.BOOL,
                          [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)])
GetTokenInformation = _proto(advapi32, "GetTokenInformation", wintypes.BOOL,
                             [wintypes.HANDLE, ctypes.c_int, LPVOID, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD)])
LookupPrivilegeValueW = _proto(advapi32, "LookupPrivilegeValueW", wintypes.BOOL,
                               [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)])
AdjustTokenPrivileges = _proto(advapi32, "AdjustTokenPrivileges", wintypes.BOOL,
                               [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                wintypes.DWORD, LPVOID, LPVOID])
SetNamedSecurityInfoW = _proto(advapi32, "SetNamedSecurityInfoW", wintypes.DWORD,
                               [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                LPVOID, LPVOID, LPVOID, LPVOID])
SetSecurityInfo = _proto(advapi32, "SetSecurityInfo", wintypes.DWORD,
                         [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                          LPVOID, LPVOID, LPVOID, LPVOID])
InitializeAcl = _proto(advapi32, "InitializeAcl", wintypes.BOOL,
                       [LPVOID, wintypes.DWORD, wintypes.DWORD])
AddAccessAllowedAceEx = _proto(advapi32, "AddAccessAllowedAceEx", wintypes.BOOL,
                               [LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, LPVOID])
GetLengthSid = _proto(advapi32, "GetLengthSid", wintypes.DWORD, [LPVOID])

if rstrtmgr is not None:
    RmStartSession = _proto(rstrtmgr, "RmStartSession", wintypes.DWORD,
                            [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.LPWSTR])
    RmRegisterResources = _proto(rstrtmgr, "RmRegisterResources", wintypes.DWORD,
                                 [wintypes.DWORD, wintypes.UINT, LPVOID,
                                  wintypes.UINT, LPVOID, wintypes.UINT, LPVOID])
    RmGetList = _proto(rstrtmgr, "RmGetList", wintypes.DWORD,
                       [wintypes.DWORD, ctypes.POINTER(wintypes.UINT),
                        ctypes.POINTER(wintypes.UINT), LPVOID,
                        ctypes.POINTER(wintypes.DWORD)])
    RmEndSession = _proto(rstrtmgr, "RmEndSession", wintypes.DWORD, [wintypes.DWORD])


# ---------------------------------------------------------------- 路径工具
def long_path(path: str) -> str:
    """转换为 \\\\?\\ 前缀的长路径形式，绕开 MAX_PATH 限制。"""
    p = str(path).replace("/", "\\")
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):  # UNC
        return "\\\\?\\UNC\\" + p[2:]
    if len(p) >= 3 and p[1] == ":" and p[2] == "\\":
        return "\\\\?\\" + p
    return p


def strip_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _is_drive_root(p: str) -> bool:
    """X:\\ 形式的卷根（保留尾反斜杠，不做 rstrip）。"""
    return len(p) == 3 and p[1] == ":" and p[2] == "\\"


def expand_long_path(path: str) -> str:
    """展开 8.3 短文件名（如 PROGRA~1）为完整长名；失败时原样返回。"""
    if "~" not in path:
        return path
    n = GetLongPathNameW(path, None, 0)
    if n <= 0:
        return path
    buf = ctypes.create_unicode_buffer(n)
    if GetLongPathNameW(path, buf, n) > 0:
        return buf.value
    return path


def norm_path(path: str) -> str:
    """
    权威路径规范化：剥掉 \\\\?\\ / \\\\?\\UNC\\ 前缀、展开 8.3 短名、
    去掉尾随分隔符（卷根 X:\\ 除外）。护栏判断与实际删除共用此函数，
    避免两种写法（前缀 / 短名 / 尾斜杠）造成语义分叉被绕过。
    """
    p = strip_prefix(str(path).replace("/", "\\"))
    p = expand_long_path(p)
    if _is_drive_root(p):
        return p
    return p.rstrip("\\")


def real_path(path: str) -> str | None:
    """
    解析路径的最终物理路径（跟随符号链接 / junction）。
    打不开（不存在/无权限）时返回 None，调用方回退到 norm_path 结果。
    """
    flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    h = CreateFileW(long_path(path), READ_CONTROL | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_ALL, None, OPEN_EXISTING, flags, None)
    if h == INVALID_HANDLE_VALUE:
        return None
    try:
        cap = 1024
        for _ in range(2):
            buf = ctypes.create_unicode_buffer(cap)
            n = GetFinalPathNameByHandleW(h, buf, cap, FILE_NAME_NORMALIZED)
            if n == 0:
                return None
            if n < cap:
                return norm_path(buf.value)
            cap = n + 1
        return None
    finally:
        CloseHandle(h)


def get_attributes(path: str) -> int:
    return GetFileAttributesW(long_path(path))


def path_exists(path: str) -> bool:
    return get_attributes(path) != INVALID_FILE_ATTRIBUTES


def is_directory(path: str) -> bool:
    a = get_attributes(path)
    return a != INVALID_FILE_ATTRIBUTES and bool(a & FILE_ATTRIBUTE_DIRECTORY)


def is_reparse_point(path: str) -> bool:
    a = get_attributes(path)
    return a != INVALID_FILE_ATTRIBUTES and bool(a & FILE_ATTRIBUTE_REPARSE_POINT)


def clear_attributes(path: str) -> bool:
    """清除只读 / 隐藏 / 系统属性。"""
    return bool(SetFileAttributesW(long_path(path), FILE_ATTRIBUTE_NORMAL))


def enum_dir(path: str):
    """枚举目录内容，返回 (名称, 是否目录, 是否重解析点, 大小)。使用长路径，支持超长目录。"""
    wp = long_path(path)
    if not wp.endswith("\\"):
        wp += "\\"
    data = WIN32_FIND_DATAW()
    handle = FindFirstFileExW(wp + "*", 1, ctypes.byref(data), 0, None, 2)
    if handle == INVALID_HANDLE_VALUE:
        return
    try:
        while True:
            name = data.cFileName
            if name not in (".", ".."):
                attrs = data.dwFileAttributes
                size = (data.nFileSizeHigh << 32) | data.nFileSizeLow
                yield (name,
                       bool(attrs & FILE_ATTRIBUTE_DIRECTORY),
                       bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT),
                       size)
            if not FindNextFileW(handle, ctypes.byref(data)):
                break
    finally:
        FindClose(handle)


# ---------------------------------------------------------------- 删除原语
def posix_delete(path: str, is_dir: bool) -> tuple[bool, int]:
    """
    POSIX 语义删除：立即从目录项摘除，即使仍有进程持有句柄。
    需要 Windows 10 1709+ / NTFS。返回 (成功, 错误码)。
    """
    flags = FILE_FLAG_OPEN_REPARSE_POINT | (FILE_FLAG_BACKUP_SEMANTICS if is_dir else 0)
    h = CreateFileW(long_path(path), DELETE | SYNCHRONIZE, FILE_SHARE_ALL,
                    None, OPEN_EXISTING, flags, None)
    if h == INVALID_HANDLE_VALUE:
        return False, ctypes.get_last_error()
    try:
        info = FILE_DISPOSITION_INFO_EX(
            FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
            | FILE_DISPOSITION_FLAG_FORCE_IMAGE_SECTION_CHECK
        )
        ok = SetFileInformationByHandle(h, FileDispositionInfoEx,
                                        ctypes.byref(info), ctypes.sizeof(info))
        if ok:
            return True, 0
        err = ctypes.get_last_error()
        # 老系统不支持 Ex，退回经典 FileDispositionInfo。
        # 经典语义是"最后一个句柄关闭时才删除"：返回 TRUE 时文件往往还在磁盘上，
        # 必须复查存在性，否则上层会误判为已删除而跳过 L2-L5。
        legacy = wintypes.BOOL(True)
        if SetFileInformationByHandle(h, FileDispositionInfo,
                                      ctypes.byref(legacy), ctypes.sizeof(legacy)):
            if not path_exists(path):
                return True, 0
            # 登记了"关句柄时删除"但对象仍在 → 按失败处理，让上层继续升级
            return False, err
        return False, ctypes.get_last_error() or err
    finally:
        CloseHandle(h)


def plain_delete(path: str, is_dir: bool) -> tuple[bool, int]:
    """常规删除（DeleteFileW / RemoveDirectoryW）。"""
    wp = long_path(path)
    ok = RemoveDirectoryW(wp) if is_dir else DeleteFileW(wp)
    return (True, 0) if ok else (False, ctypes.get_last_error())


def schedule_delete_on_reboot(path: str) -> bool:
    """登记重启时删除（写入 PendingFileRenameOperations），需要管理员权限。
    登记前先查现有条目去重，避免多次运行重复登记、拖慢开机。"""
    try:
        existing = _pending_reboot_sources()
    except Exception:  # noqa
        existing = set()
    lp = long_path(path)
    src = "\\??\\" + (lp[4:] if lp.startswith("\\\\?\\") else lp)
    if src.lower() in existing:
        return True  # 之前已登记过，视为成功
    return bool(MoveFileExW(lp, None, MOVEFILE_DELAY_UNTIL_REBOOT))


HKEY_LOCAL_MACHINE = 0x80000002
RRF_RT_REG_MULTI_SZ = 0x00020000
RegGetValueW = _proto(advapi32, "RegGetValueW", wintypes.LONG,
                      [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                       wintypes.DWORD, LPVOID, LPVOID, ctypes.POINTER(wintypes.DWORD)])


def _pending_reboot_sources() -> set[str]:
    """读取 PendingFileRenameOperations 中已登记的源路径（小写、含 \\??\\ 前缀）。"""
    subkey = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    size = wintypes.DWORD(0)
    rc = RegGetValueW(HKEY_LOCAL_MACHINE, subkey, "PendingFileRenameOperations",
                      RRF_RT_REG_MULTI_SZ, None, None, ctypes.byref(size))
    if rc not in (0, 234):  # 234 = ERROR_MORE_DATA，表示需要缓冲
        return set()
    buf = ctypes.create_unicode_buffer(max(1, size.value // 2))
    rc = RegGetValueW(HKEY_LOCAL_MACHINE, subkey, "PendingFileRenameOperations",
                      RRF_RT_REG_MULTI_SZ, None, buf, ctypes.byref(size))
    if rc != 0:
        return set()
    # REG_MULTI_SZ：NUL 分隔、双 NUL 结尾；条目按 (源, 目标) 成对出现
    items = [s for s in buf.raw.decode("utf-16-le", errors="ignore").split("\x00") if s]
    return {items[i].lower() for i in range(0, len(items) - 1, 2)}


def overwrite_file(path: str, passes: int = 1, chunk: int = 1 << 20) -> bool:
    """删除前用随机数据覆写文件内容，降低被恢复的可能。"""
    # 符号链接只允许"删链接"，绝不允许覆写 —— 普通打开会跟随到目标文件，
    # 把用户没选定的内容整段破坏掉。
    attrs = get_attributes(path)
    if attrs != INVALID_FILE_ATTRIBUTES and attrs & FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    h = CreateFileW(long_path(path), GENERIC_WRITE, FILE_SHARE_ALL, None,
                    OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, None)
    if h == INVALID_HANDLE_VALUE:
        return False
    try:
        size = ctypes.c_longlong(0)
        if not GetFileSizeEx(h, ctypes.byref(size)) or size.value <= 0:
            return True
        total = size.value
        for _ in range(max(1, passes)):
            SetFilePointerEx(h, 0, None, 0)
            remaining = total
            while remaining > 0:
                n = min(chunk, remaining)
                buf = os.urandom(n)
                written = wintypes.DWORD(0)
                if not WriteFile(h, buf, n, ctypes.byref(written), None):
                    return False
                remaining -= written.value or n
            FlushFileBuffers(h)
        return True
    finally:
        CloseHandle(h)


# ---------------------------------------------------------------- 权限 / 所有权
_PRIVILEGES = ("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege",
               "SeSecurityPrivilege", "SeDebugPrivilege")


def enable_privileges() -> list[str]:
    """为当前进程开启强删所需的特权，返回成功启用的特权名。"""
    enabled = []
    token = wintypes.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        return enabled
    try:
        for name in _PRIVILEGES:
            luid = LUID()
            if not LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                continue
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            ctypes.set_last_error(0)
            AdjustTokenPrivileges(token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
            if ctypes.get_last_error() == 0:
                enabled.append(name)
    finally:
        CloseHandle(token)
    return enabled


_current_sid_cache = None


def get_current_user_sid():
    """取当前进程用户的 SID（缓存）。"""
    global _current_sid_cache
    if _current_sid_cache is not None:
        return _current_sid_cache
    token = wintypes.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return None
    try:
        size = wintypes.DWORD(0)
        GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(size))
        if size.value == 0:
            return None
        buf = ctypes.create_string_buffer(size.value)
        if not GetTokenInformation(token, TokenUser, buf, size.value, ctypes.byref(size)):
            return None
        tu = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
        sid_len = GetLengthSid(tu.User.Sid)
        sid_copy = ctypes.create_string_buffer(sid_len)
        ctypes.memmove(sid_copy, tu.User.Sid, sid_len)
        _current_sid_cache = sid_copy
        return sid_copy
    finally:
        CloseHandle(token)


def _build_full_control_acl(sid, inherit: bool):
    """构造一个仅含"当前用户完全控制"的全新 DACL。"""
    sid_len = GetLengthSid(sid)
    acl_size = 8 + 8 + sid_len + 64
    acl = ctypes.create_string_buffer(acl_size)
    if not InitializeAcl(acl, acl_size, ACL_REVISION):
        return None
    flags = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) if inherit else 0
    if not AddAccessAllowedAceEx(acl, ACL_REVISION, flags, FILE_ALL_ACCESS, sid):
        return None
    return acl


def take_ownership(path: str, is_dir: bool) -> bool:
    """
    接管文件/目录：先夺取所有权（依赖 SeTakeOwnershipPrivilege 绕过 DACL），
    再重写 DACL 授予当前用户完全控制。
    """
    sid = get_current_user_sid()
    if sid is None:
        return False
    wp = long_path(path)
    flags = FILE_FLAG_OPEN_REPARSE_POINT | (FILE_FLAG_BACKUP_SEMANTICS if is_dir else 0)
    changed = False

    # 1) 夺取所有权（句柄方式，天然支持长路径）
    h = CreateFileW(wp, WRITE_OWNER | READ_CONTROL, FILE_SHARE_ALL, None,
                    OPEN_EXISTING, flags, None)
    if h != INVALID_HANDLE_VALUE:
        try:
            if SetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                               ctypes.cast(sid, LPVOID), None, None, None) == 0:
                changed = True
        finally:
            CloseHandle(h)
    else:
        namebuf = ctypes.create_unicode_buffer(wp)
        if SetNamedSecurityInfoW(namebuf, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                 ctypes.cast(sid, LPVOID), None, None, None) == 0:
            changed = True

    # 2) 重写 DACL
    acl = _build_full_control_acl(sid, is_dir)
    if acl is not None:
        h = CreateFileW(wp, WRITE_DAC | READ_CONTROL, FILE_SHARE_ALL, None,
                        OPEN_EXISTING, flags, None)
        if h != INVALID_HANDLE_VALUE:
            try:
                if SetSecurityInfo(h, SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   None, None, ctypes.cast(acl, LPVOID), None) == 0:
                    changed = True
            finally:
                CloseHandle(h)
        else:
            namebuf = ctypes.create_unicode_buffer(wp)
            if SetNamedSecurityInfoW(namebuf, SE_FILE_OBJECT,
                                     DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                     None, None, ctypes.cast(acl, LPVOID), None) == 0:
                changed = True

    clear_attributes(path)
    return changed


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------- 占用检测
def get_pids_using_file(path: str) -> tuple[list[int], int]:
    """
    NtQueryInformationFile(FileProcessIdsUsingFileInformation)：
    直接向内核索取"当前打开此文件的进程 PID 列表"，比枚举全系统句柄快几个数量级。
    返回 (pid 列表, 错误码)：错误码非 0 表示"检测不可用"（独占打开/权限不足等），
    与"确实无人占用"（空列表 + 错误码 0）区分，调用方据此决定是否降级。
    """
    h = CreateFileW(long_path(path), FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_ALL,
                    None, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
    if h == INVALID_HANDLE_VALUE:
        return [], ctypes.get_last_error()
    try:
        size = 4096
        for _ in range(6):
            buf = ctypes.create_string_buffer(size)
            iosb = IO_STATUS_BLOCK()
            status = NtQueryInformationFile(h, ctypes.byref(iosb), buf, size,
                                            FileProcessIdsUsingFileInformation)
            if status == STATUS_INFO_LENGTH_MISMATCH or (status & 0xFFFFFFFF) == 0xC0000004:
                size *= 4
                continue
            if status != STATUS_SUCCESS:
                return [], int(RtlNtStatusToDosError(status))
            n = ctypes.cast(buf, ctypes.POINTER(wintypes.ULONG)).contents.value
            ptr_size = ctypes.sizeof(ULONG_PTR)
            arr = ctypes.cast(ctypes.byref(buf, ptr_size),
                              ctypes.POINTER(ULONG_PTR * max(n, 1))).contents
            return [int(arr[i]) for i in range(n)], 0
        return [], 0
    finally:
        CloseHandle(h)


def get_process_image(pid: int) -> str:
    if pid in (0, 4):
        return "System"
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        h = OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        CloseHandle(h)


def restart_manager_processes(paths: list[str]) -> list[dict]:
    """Restart Manager：列出锁定这些资源的应用/服务（与 Windows Update 释放文件用的是同一机制）。"""
    if rstrtmgr is None or not paths:
        return []
    session = wintypes.DWORD(0)
    key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)
    if RmStartSession(ctypes.byref(session), 0, key) != 0:
        return []
    try:
        arr = (wintypes.LPCWSTR * len(paths))(*[long_path(p) for p in paths])
        if RmRegisterResources(session, len(paths), arr, 0, None, 0, None) != 0:
            return []
        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        rc = RmGetList(session, ctypes.byref(needed), ctypes.byref(count),
                       None, ctypes.byref(reasons))
        if rc not in (0, ERROR_MORE_DATA) or needed.value == 0:
            return []
        infos = (RM_PROCESS_INFO * needed.value)()
        count = wintypes.UINT(needed.value)
        if RmGetList(session, ctypes.byref(needed), ctypes.byref(count),
                     infos, ctypes.byref(reasons)) != 0:
            return []
        out = []
        for i in range(count.value):
            info = infos[i]
            out.append({
                "pid": int(info.Process.dwProcessId),
                "name": info.strAppName or "",
                "service": info.strServiceShortName or "",
                "restartable": bool(info.bRestartable),
                "image": get_process_image(int(info.Process.dwProcessId)),
            })
        return out
    finally:
        RmEndSession(session)


# ---------------------------------------------------------------- 句柄强制关闭
def _query_system_handles():
    """枚举全系统内核句柄表。"""
    size = 4 * 1024 * 1024
    for _ in range(12):
        buf = ctypes.create_string_buffer(size)
        ret = wintypes.ULONG(0)
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, size,
                                          ctypes.byref(ret))
        if (status & 0xFFFFFFFF) == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
            size = max(int(ret.value * 1.5), size * 2)
            continue
        if status != STATUS_SUCCESS:
            return None, 0
        n = ctypes.cast(buf, ctypes.POINTER(ULONG_PTR)).contents.value
        entry_off = ctypes.sizeof(ULONG_PTR) * 2  # NumberOfHandles + Reserved
        entries = ctypes.cast(ctypes.byref(buf, entry_off),
                              ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * n)).contents
        return (buf, entries), n
    return None, 0


def _detect_file_type_index() -> int:
    """运行时探测 File 对象的 ObjectTypeIndex（各 Windows 版本取值不同）。"""
    h = CreateFileW("NUL", FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, None, OPEN_EXISTING, 0, None)
    if h == INVALID_HANDLE_VALUE:
        return -1
    try:
        data, n = _query_system_handles()
        if data is None:
            return -1
        _, entries = data
        mypid = GetCurrentProcessId()
        hval = ctypes.cast(h, LPVOID).value
        for i in range(n):
            e = entries[i]
            if e.UniqueProcessId == mypid and e.HandleValue == hval:
                return int(e.ObjectTypeIndex)
        return -1
    finally:
        CloseHandle(h)


def _handle_target_path(dup: wintypes.HANDLE) -> str:
    """只对磁盘文件求路径 —— GetFileType 先过滤掉管道/套接字，避免 API 挂死。"""
    if GetFileType(dup) != FILE_TYPE_DISK:
        return ""
    cap = 1024
    for _ in range(3):
        buf = ctypes.create_unicode_buffer(cap)
        n = GetFinalPathNameByHandleW(dup, buf, cap, FILE_NAME_NORMALIZED)
        if n == 0:
            return ""
        if n < cap:  # 返回值不含结尾 NUL，n < cap 才写全
            return buf.value
        cap = n + 1  # 缓冲不足按需扩容重试，不再直接放弃超长路径
    return ""


# 强关句柄 / 结束进程都绝不能碰的系统关键进程
CRITICAL_PROCESSES = frozenset((
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "smss.exe", "svchost.exe", "system", "fontdrvhost.exe", "dwm.exe",
))


def force_close_handles(targets: list[str], progress=None) -> tuple[int, list[str]]:
    """
    枚举全系统句柄，找出指向 targets 的文件句柄，
    用 DuplicateHandle(DUPLICATE_CLOSE_SOURCE) 在持有者进程中强行关闭。
    返回 (关闭数量, 受影响进程描述列表)。
    """
    wanted = set()
    for t in targets:
        wanted.add(norm_path(t).lower())
    if not wanted:
        return 0, []

    type_index = _detect_file_type_index()
    data, n = _query_system_handles()
    if data is None:
        return 0, []
    _, entries = data

    mypid = GetCurrentProcessId()
    cur = GetCurrentProcess()
    proc_cache: dict[int, wintypes.HANDLE] = {}
    closed = 0
    affected: set[str] = set()

    try:
        for i in range(n):
            if progress and (i & 0x3FFF) == 0:
                progress(i, n)
            e = entries[i]
            pid = int(e.UniqueProcessId)
            if pid in (0, 4, mypid) or e.GrantedAccess == 0:
                continue
            if type_index >= 0 and e.ObjectTypeIndex != type_index:
                continue
            # 已知会导致同步 API 挂死的访问掩码，直接跳过
            if e.GrantedAccess in (0x0012019F, 0x00120189, 0x00100000):
                continue

            if pid not in proc_cache:
                proc_cache[pid] = OpenProcess(PROCESS_DUP_HANDLE, False, pid) or None
            ph = proc_cache[pid]
            if not ph:
                continue

            src = wintypes.HANDLE(e.HandleValue)
            dup = wintypes.HANDLE()
            if not DuplicateHandle(ph, src, cur, ctypes.byref(dup), 0, False,
                                   DUPLICATE_SAME_ACCESS):
                continue
            try:
                target = _handle_target_path(dup)
            finally:
                CloseHandle(dup)
            if not target:
                continue
            if norm_path(target).lower() not in wanted:
                continue

            # 系统关键进程持有的句柄一律不强关：强拆 csrss/lsass 等进程的句柄
            # 可能直接引发进程崩溃甚至蓝屏。
            img = get_process_image(pid)
            base = os.path.basename(img).lower() if img else ""
            if base in CRITICAL_PROCESSES:
                affected.add(f"{base or '系统进程'} (PID {pid}) 已跳过（关键进程）")
                continue
            if DuplicateHandle(ph, src, None, None, 0, False, DUPLICATE_CLOSE_SOURCE):
                closed += 1
                affected.add(f"{base or '未知进程'} (PID {pid})")
    finally:
        for ph in proc_cache.values():
            if ph:
                CloseHandle(ph)
    return closed, sorted(affected)


def kill_process(pid: int) -> bool:
    if pid in (0, 4):
        return False
    h = OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False
    try:
        return bool(TerminateProcess(h, 1))
    finally:
        CloseHandle(h)


def error_text(code: int) -> str:
    """把 Win32 错误码翻译成中文说明。"""
    table = {
        0: "成功",
        2: "文件不存在",
        3: "路径不存在",
        5: "拒绝访问（权限不足）",
        19: "介质写保护",
        30: "读取设备错误",
        32: "文件被其他进程占用",
        33: "文件区域被锁定",
        50: "不支持该请求",
        87: "参数错误",
        123: "文件名或路径语法错误",
        145: "目录非空",
        1224: "文件已被映射为镜像（正在运行的程序）",
    }
    if code in table:
        return table[code]
    try:
        return ctypes.FormatError(code).strip() or f"错误码 {code}"
    except Exception:
        return f"错误码 {code}"
