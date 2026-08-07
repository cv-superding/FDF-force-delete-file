"""
gui.py — FDF 强制删除工具 图形界面（纯 ctypes Win32 原生控件，无第三方依赖）

外观改进：
  · 莫奈（Monet）印象派粉彩配色：渐变背景 + 自绘圆角按钮 / 复选框 / 分组框
  · 柔和低饱和色调（淡紫 / 灰蓝 / 暖粉 / 米黄 / 薄荷绿），统一按钮、背景、
    文字、边框与卡片配色，营造温暖通透的油画般氛围
  · 嵌入 comctl32 v6 视觉样式清单（由 fdf.manifest 提供）
  · Segoe UI 字体（标题加粗放大）
  · 标题栏 + 副标题 + 选项分组框（Group Box）
  · 目标列表改为 ListView（报告视图，含「路径 / 类型 / 状态」三列）
  · 应用程序图标（标题栏与任务栏），由 fdf.manifest + --icon 提供

删除与扫描在后台线程执行，通过 SetTimer 轮询线程安全队列来刷新 UI，
避免跨线程直接操作控件导致崩溃。
"""

import ctypes
import os
import sys
import threading
from ctypes import wintypes

# 让 fdf 包可被找到（gui.py 位于 src/fdf/，故把 src 加入 path）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fdf.engine import (ForceDeleter, Options, ItemResult, is_protected, format_size,
                        STATUS_DELETED, STATUS_REBOOT, STATUS_FAILED,
                        STATUS_MISSING, STATUS_BLOCKED)
from fdf import winapi as w

# ---------------------------------------------------------------- DLL
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
comdlg32 = ctypes.WinDLL("comdlg32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
ole32 = ctypes.WinDLL("ole32", use_last_error=True)
comctl32 = ctypes.WinDLL("comctl32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# ---------------------------------------------------------------- 常量
WM_CREATE = 0x0001
WM_COMMAND = 0x0111
WM_DESTROY = 0x0002
WM_SIZE = 0x0005
WM_GETMINMAXINFO = 0x0024
WM_TIMER = 0x0113
WM_SETTEXT = 0x000C
WM_SETFONT = 0x0030
WM_SETICON = 0x0080
WM_DROPFILES = 0x0233
WM_COPYDATA = 0x004A
WM_COPYGLOBALDATA = 0x0049
MSGFLT_ALLOW = 1
GWLP_WNDPROC = -4
CF_HDROP = 15
CF_UNICODETEXT = 13
TYMED_HGLOBAL = 1
DVASPECT_CONTENT = 1
DROPEFFECT_NONE = 0
DROPEFFECT_COPY = 1
MSGFLT_ADD = 1
S_OK = 0
E_NOINTERFACE = -2147467262      # 0x80004002

WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_VISIBLE = 0x10000000
WS_CHILD = 0x40000000
WS_BORDER = 0x00800000
WS_VSCROLL = 0x00200000
WS_TABSTOP = 0x00010000
ES_MULTILINE = 0x0004
ES_AUTOVSCROLL = 0x0040
ES_READONLY = 0x0800
BS_PUSHBUTTON = 0x0000
BS_AUTOCHECKBOX = 0x0003
SS_GROUPBOX = 0x0007
SS_LEFT = 0x0000

SW_SHOW = 5
NULL = 0
IDC_ARROW = 32512
CW_USEDEFAULT = -2147483648

ICC_PROGRESS_CLASS = 0x00000020
PBM_SETRANGE = 0x0401
PBM_SETPOS = 0x0402
PROGRESS_CLASSW = "msctls_progress32"

EM_SETSEL = 0x00B1
EM_SCROLLCARET = 0x00B7
BM_GETCHECK = 0x00F0
BM_SETCHECK = 0x00F1
BST_CHECKED = 0x0001
BST_UNCHECKED = 0x0000

# ListView
WC_LISTVIEWW = "SysListView32"
LVS_REPORT = 0x0001
LVS_SINGLESEL = 0x0004
LVS_SHOWSELALWAYS = 0x0008
LVS_NOSORTHEADER = 0x8000
LVS_EX_FULLROWSELECT = 0x00000020
LVCF_FMT = 0x0001
LVCF_WIDTH = 0x0002
LVCF_TEXT = 0x0004
LVIF_TEXT = 0x0001
LVCFMT_LEFT = 0x0000
LVM_FIRST = 0x1000
LVM_SETCOLUMNWIDTH = LVM_FIRST + 30
LVM_INSERTCOLUMNW = LVM_FIRST + 97
LVM_INSERTITEMW = LVM_FIRST + 77
LVM_SETITEMW = LVM_FIRST + 76
LVM_DELETEALLITEMS = LVM_FIRST + 9
LVM_GETNEXTITEM = LVM_FIRST + 12
LVM_GETITEMCOUNT = LVM_FIRST + 4
LVM_SETEXTENDEDLISTVIEWSTYLE = LVM_FIRST + 54
LVM_SETBKCOLOR = 0x1001
LVM_SETTEXTBKCOLOR = 0x1026
LVNI_SELECTED = 0x0002
ICON_BIG = 1
ICON_SMALL = 0
IMAGE_ICON = 1
LR_LOADFROMFILE = 0x0010
LR_DEFAULTSIZE = 0x0040

SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010

# 控件 ID
ID_ADD_FILE = 1001
ID_ADD_DIR = 1002
ID_REMOVE = 1003
ID_CLEAR = 1004
ID_SCAN = 1005
ID_DELETE = 1006
ID_CHK_UNLOCK = 1010
ID_CHK_KILL = 1011
ID_CHK_OWN = 1012
ID_CHK_REBOOT = 1013
ID_LIST = 1020
ID_LOG = 1030
ID_PROGRESS = 1040
ID_STATUS = 1050
ID_GRP_OPT = 1060
ID_LBL_LOG = 1070
ID_PASTE = 1007


# ================================================================ 莫奈配色
# 低饱和度印象派粉彩。Win32 COLORREF 为 0xBBGGRR（蓝、绿、红）。
MONET_TOP_BG     = 0xEAF3F8   # 顶部暖米黄
MONET_BOTTOM_BG  = 0xF5E7EC   # 底部淡紫
MONET_LILAC      = 0xE4B6C9   # 朦胧淡紫
MONET_GRAYBLUE   = 0xD6C4A7   # 灰蓝
MONET_WARMPINK   = 0xD7D4F2   # 暖粉
MONET_CREAM      = 0xD7ECF5   # 米黄
MONET_MINT       = 0xD3E2C2   # 薄荷绿
MONET_BTN_FACE   = 0xE4E7EF   # 工具按钮常态
MONET_BTN_HOVER  = 0xEED9E5   # 工具按钮悬停
MONET_BTN_PRESS  = 0xE7C8D8   # 工具按钮按下
MONET_BTN_BORDER = 0xD6B0C4   # 工具按钮描边
MONET_DEL_FACE   = 0xD1DFC7   # 主按钮（开始删除）常态·薄荷
MONET_DEL_HOVER  = 0xC4D5B6   # 主按钮悬停
MONET_DEL_PRESS  = 0xB7C9A7   # 主按钮按下
MONET_DEL_BORDER = 0xAABE96   # 主按钮描边
MONET_TEXT       = 0x58444A   # 文字·深灰紫
MONET_TITLE      = 0x744A60   # 标题·深藕荷
MONET_LIST_BG    = 0xFAF3F7   # 列表底色
MONET_LIST_HL    = 0xF0D4E2   # 拖拽高亮·淡紫
MONET_EDIT_BG    = 0xF0F7FA   # 日志底色
MONET_HDR_BG     = 0xEED9E4   # 列表表头底色
MONET_PROG_BAR   = 0xAABE96   # 进度条
MONET_PROG_BG    = 0xF0E4EA   # 进度条底

# 自绘 / 消息 / 样式常量
BS_OWNERDRAW     = 0x000B
WM_PAINT         = 0x000F
WM_ERASEBKGND    = 0x0014
WM_DRAWITEM      = 0x002B
WM_NOTIFY        = 0x004E
WM_CTLCOLORSTATIC = 0x0138
WM_CTLCOLOREDIT  = 0x0135
WM_MOUSEMOVE     = 0x0200
WM_MOUSELEAVE    = 0x02A3
ODT_BUTTON       = 4
ODS_SELECTED     = 0x0001
ODS_DISABLED     = 0x0004
ODS_CHECKED      = 0x0008
ODS_FOCUS        = 0x0010
CDDS_PREPAINT     = 0x00000001
CDDS_ITEMPREPAINT = 0x00010001
CDRF_DODEFAULT    = 0x00000000
CDRF_NEWFONT      = 0x00000002
CDRF_NOTIFYITEMDRAW = 0x00000020
NM_CUSTOMDRAW    = 0xFFFFFFF4   # -12
GRADIENT_FILL_RECT_V = 0x0001
TRANSPARENT      = 1
OPAQUE           = 2
NULL_BRUSH       = 5
PS_SOLID         = 0
PBM_SETBARCOLOR  = 0x040A
PBM_SETBKCOLOR   = 0x040C
LVM_GETHEADER    = 0x101F


# ---------------------------------------------------------------- 结构
class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", ctypes.c_void_p),
        ("cbClsExtra", wintypes.INT),
        ("cbWndExtra", wintypes.INT),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HANDLE),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HANDLE),
    ]


class INITCOMMONCONTROLSEX(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("dwICC", wintypes.DWORD)]


class OPENFILENAMEW(ctypes.Structure):
    _fields_ = [
        ("lStructSize", wintypes.DWORD),
        ("hwndOwner", wintypes.HWND),
        ("hInstance", wintypes.HINSTANCE),
        ("lpstrFilter", wintypes.LPCWSTR),
        ("lpstrCustomFilter", wintypes.LPWSTR),
        ("nMaxCustFilter", wintypes.DWORD),
        ("nFilterIndex", wintypes.DWORD),
        ("lpstrFile", wintypes.LPWSTR),
        ("nMaxFile", wintypes.DWORD),
        ("lpstrFileTitle", wintypes.LPWSTR),
        ("nMaxFileTitle", wintypes.DWORD),
        ("lpstrInitialDir", wintypes.LPCWSTR),
        ("lpstrTitle", wintypes.LPCWSTR),
        ("Flags", wintypes.DWORD),
        ("nFileOffset", wintypes.WORD),
        ("nFileExtension", wintypes.WORD),
        ("lpstrDefExt", wintypes.LPCWSTR),
        ("lCustData", wintypes.LPARAM),
        ("lpfnHook", ctypes.c_void_p),
        ("lpTemplateName", wintypes.LPCWSTR),
        ("pvReserved", ctypes.c_void_p),
        ("dwReserved", wintypes.DWORD),
        ("FlagsEx", wintypes.DWORD),
    ]


class BROWSEINFOW(ctypes.Structure):
    _fields_ = [
        ("hwndOwner", wintypes.HWND),
        ("pidlRoot", ctypes.c_void_p),
        ("pszDisplayName", wintypes.LPWSTR),
        ("lpszTitle", wintypes.LPCWSTR),
        ("ulFlags", wintypes.UINT),
        ("lpfn", ctypes.c_void_p),
        ("lParam", ctypes.c_void_p),
        ("iImage", wintypes.INT),
    ]


class RECT(ctypes.Structure):
    _fields_ = [("left", wintypes.LONG), ("top", wintypes.LONG),
                ("right", wintypes.LONG), ("bottom", wintypes.LONG)]


class POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


class MSG(ctypes.Structure):
    _fields_ = [("hwnd", wintypes.HWND), ("message", wintypes.UINT),
                ("wParam", wintypes.WPARAM), ("lParam", wintypes.LPARAM),
                ("time", wintypes.DWORD), ("pt", POINT)]


class LOGFONTW(ctypes.Structure):
    _fields_ = [
        ("lfHeight", wintypes.LONG),
        ("lfWidth", wintypes.LONG),
        ("lfEscapement", wintypes.LONG),
        ("lfOrientation", wintypes.LONG),
        ("lfWeight", wintypes.LONG),
        ("lfItalic", wintypes.BYTE),
        ("lfUnderline", wintypes.BYTE),
        ("lfStrikeOut", wintypes.BYTE),
        ("lfCharSet", wintypes.BYTE),
        ("lfOutPrecision", wintypes.BYTE),
        ("lfClipPrecision", wintypes.BYTE),
        ("lfQuality", wintypes.BYTE),
        ("lfPitchAndFamily", wintypes.BYTE),
        ("lfFaceName", wintypes.WCHAR * 32),
    ]


class LVCOLUMNW(ctypes.Structure):
    _fields_ = [
        ("mask", wintypes.UINT),
        ("fmt", ctypes.c_int),
        ("cx", ctypes.c_int),
        ("pszText", wintypes.LPWSTR),
        ("cchTextMax", ctypes.c_int),
        ("iSubItem", ctypes.c_int),
    ]


class LVITEMW(ctypes.Structure):
    _fields_ = [
        ("mask", wintypes.UINT),
        ("iItem", ctypes.c_int),
        ("iSubItem", ctypes.c_int),
        ("state", wintypes.UINT),
        ("stateMask", wintypes.UINT),
        ("pszText", wintypes.LPWSTR),
        ("cchTextMax", ctypes.c_int),
        ("iImage", ctypes.c_int),
        ("lParam", wintypes.LPARAM),
        ("iIndent", ctypes.c_int),
    ]


WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong, wintypes.HWND,
                             wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


# ---------------------------------------------------------------- COM 拖放结构
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_byte * 8),
    ]


class POINTL(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class MINMAXINFO(ctypes.Structure):
    _fields_ = [
        ("ptReserved", POINTL),
        ("ptMaxSize", POINTL),
        ("ptMaxPosition", POINTL),
        ("ptMinTrackSize", POINTL),
        ("ptMaxTrackSize", POINTL),
    ]


class FORMATETC(ctypes.Structure):
    _fields_ = [
        ("cfFormat", wintypes.USHORT),
        ("ptd", ctypes.c_void_p),
        ("dwAspect", wintypes.DWORD),
        ("lindex", ctypes.c_long),
        ("tymed", wintypes.DWORD),
    ]


class STGMEDIUM(ctypes.Structure):
    _fields_ = [
        ("tymed", wintypes.DWORD),
        ("_pad", wintypes.DWORD),
        ("hGlobal", wintypes.HANDLE),
        ("pUnkForRelease", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------- 函数原型
def _p(dll, name, restype, argtypes):
    fn = getattr(dll, name)
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


def _resolve(dlls, name, restype, argtypes):
    """跨 DLL 解析 API：优先列表首项（真实 Windows 的标准位置），缺失则回退。"""
    last = None
    for d in dlls:
        try:
            fn = getattr(d, name)
            fn.restype = restype
            fn.argtypes = argtypes
            return fn
        except Exception as e:  # noqa
            last = e
    raise last


RegisterClassExW = _p(user32, "RegisterClassExW", ctypes.c_ushort, [ctypes.c_void_p])
CreateWindowExW = _p(user32, "CreateWindowExW", wintypes.HWND,
                     [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                      wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                      ctypes.c_int, wintypes.HWND, wintypes.HMENU,
                      wintypes.HINSTANCE, ctypes.c_void_p])
DefWindowProcW = _p(user32, "DefWindowProcW", ctypes.c_longlong,
                    [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM])
ShowWindow = _p(user32, "ShowWindow", wintypes.BOOL, [wintypes.HWND, ctypes.c_int])
UpdateWindow = _p(user32, "UpdateWindow", wintypes.BOOL, [wintypes.HWND])
GetMessageW = _p(user32, "GetMessageW", wintypes.INT,
                 [ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.UINT])
TranslateMessage = _p(user32, "TranslateMessage", wintypes.BOOL, [ctypes.c_void_p])
DispatchMessageW = _p(user32, "DispatchMessageW", wintypes.LPARAM, [ctypes.c_void_p])
PostQuitMessage = _p(user32, "PostQuitMessage", None, [ctypes.c_int])
SetWindowTextW = _p(user32, "SetWindowTextW", wintypes.BOOL,
                    [wintypes.HWND, wintypes.LPCWSTR])
GetClientRect = _p(user32, "GetClientRect", wintypes.BOOL,
                   [wintypes.HWND, ctypes.c_void_p])
SetWindowPos = _p(user32, "SetWindowPos", wintypes.BOOL,
                  [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                   ctypes.c_int, ctypes.c_int, wintypes.UINT])
SendMessageW = _p(user32, "SendMessageW", wintypes.LPARAM,
                  [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM])
SetTimer = _p(user32, "SetTimer", ctypes.c_size_t,
              [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p])
KillTimer = _p(user32, "KillTimer", wintypes.BOOL, [wintypes.HWND, ctypes.c_size_t])
LoadCursorW = _p(user32, "LoadCursorW", wintypes.HANDLE,
                 [wintypes.HINSTANCE, wintypes.LPCWSTR])
LoadImageW = _p(user32, "LoadImageW", wintypes.HANDLE,
                [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                 ctypes.c_int, ctypes.c_int, wintypes.UINT])
GetModuleHandleW = _p(kernel32, "GetModuleHandleW", wintypes.HINSTANCE,
                      [wintypes.LPCWSTR])
InitCommonControlsEx = _p(comctl32, "InitCommonControlsEx", wintypes.BOOL,
                          [ctypes.c_void_p])
GetOpenFileNameW = _p(comdlg32, "GetOpenFileNameW", wintypes.BOOL, [ctypes.c_void_p])
SHBrowseForFolderW = _p(shell32, "SHBrowseForFolderW", ctypes.c_void_p, [ctypes.c_void_p])
SHGetPathFromIDListW = _p(shell32, "SHGetPathFromIDListW", wintypes.BOOL,
                          [ctypes.c_void_p, wintypes.LPWSTR])
CoTaskMemFree = _p(ole32, "CoTaskMemFree", None, [ctypes.c_void_p])
DragAcceptFiles = _resolve([user32, shell32], "DragAcceptFiles", None,
                           [wintypes.HWND, wintypes.BOOL])
DragQueryFileW = _resolve([shell32, user32], "DragQueryFileW", wintypes.UINT,
                          [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT])
DragFinish = _resolve([shell32, user32], "DragFinish", None, [wintypes.HANDLE])
try:
    ChangeWindowMessageFilterEx = _resolve(
        [user32, shell32], "ChangeWindowMessageFilterEx", wintypes.BOOL,
        [wintypes.HWND, wintypes.UINT, wintypes.DWORD, ctypes.c_void_p])
except Exception:  # noqa
    ChangeWindowMessageFilterEx = None

def _is_elevated():
    """当前进程是否以管理员（高完整性级别）运行。"""
    try:
        h = wintypes.HANDLE()
        if not OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h)):
            return False
        ev = wintypes.DWORD()
        retlen = wintypes.DWORD()
        if not GetTokenInformation(h, TokenElevation, ctypes.byref(ev),
                                   ctypes.sizeof(ev), ctypes.byref(retlen)):
            CloseHandle(h)
            return False
        CloseHandle(h)
        return bool(ev.value)
    except Exception:  # noqa
        return False


def _relaunch_non_elevated():
    """以普通权限（中等完整性级别）重启自身。成功返回 True。

    做法：取资源管理器（Shell 窗口）的令牌（中等 IL），派生一个主令牌，
    再用 CreateProcessAsUser 启动同一 exe。新进程与拖放源（资源管理器）同级，
    UIPI 不再拦截拖放。失败返回 False（调用方应降级为「仅警告 + 粘贴兜底」。
    """
    try:
        hwnd = GetShellWindow()
        if not hwnd:
            return False
        pid = wintypes.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        # PROCESS_QUERY_INFORMATION = 0x400
        hproc = OpenProcess(0x400, False, pid)
        if not hproc:
            return False
        htok = wintypes.HANDLE()
        if not OpenProcessToken(hproc, TOKEN_DUPLICATE | TOKEN_QUERY,
                                ctypes.byref(htok)):
            CloseHandle(hproc)
            return False
        newtok = wintypes.HANDLE()
        if not DuplicateTokenEx(htok, MAXIMUM_ALLOWED, None,
                                SecurityImpersonation, TokenPrimary,
                                ctypes.byref(newtok)):
            CloseHandle(htok)
            CloseHandle(hproc)
            return False
        exe = sys.executable
        cmd = ctypes.create_unicode_buffer('"%s" --_demoted' % exe)
        # 标记子进程，避免在某些异常环境下被再次判定为提权而陷入重启循环
        os.environ["FDF_DEMOTED"] = "1"
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        pi = PROCESS_INFORMATION()
        ok = CreateProcessAsUserW(newtok, None, cmd, None, None, False, 0,
                                  None, None, ctypes.byref(si), ctypes.byref(pi))
        CloseHandle(newtok)
        CloseHandle(htok)
        CloseHandle(hproc)
        if ok and pi.hProcess:
            CloseHandle(pi.hProcess)
            if pi.hThread:
                CloseHandle(pi.hThread)
            return True
        return False
    except Exception:  # noqa
        return False


# --- OLE 拖放（IDropTarget）：提权窗口唯一可靠的拖放通道 ---
OleInitialize = _p(ole32, "OleInitialize", ctypes.c_long, [ctypes.c_void_p])
OleUninitialize = _p(ole32, "OleUninitialize", None, [])
RegisterDragDrop = _p(ole32, "RegisterDragDrop", ctypes.c_long,
                      [wintypes.HWND, ctypes.c_void_p])
RevokeDragDrop = _p(ole32, "RevokeDragDrop", ctypes.c_long, [wintypes.HWND])
ReleaseStgMedium = _p(ole32, "ReleaseStgMedium", None, [ctypes.c_void_p])
GlobalLock = _p(kernel32, "GlobalLock", ctypes.c_void_p, [wintypes.HANDLE])
GlobalUnlock = _p(kernel32, "GlobalUnlock", wintypes.BOOL, [wintypes.HANDLE])


# --- 自降级（提权进程自动以普通权限重启自身，使拖放不被 UIPI 拦截）---
GetCurrentProcess = _p(kernel32, "GetCurrentProcess", wintypes.HANDLE, [])
OpenProcess = _p(kernel32, "OpenProcess", wintypes.HANDLE,
                 [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD])
GetShellWindow = _p(user32, "GetShellWindow", wintypes.HWND, [])
GetWindowThreadProcessId = _p(user32, "GetWindowThreadProcessId", wintypes.DWORD,
                             [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)])
OpenProcessToken = _p(advapi32, "OpenProcessToken", wintypes.BOOL,
                      [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)])
GetTokenInformation = _p(advapi32, "GetTokenInformation", wintypes.BOOL,
                         [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)])
DuplicateTokenEx = _p(advapi32, "DuplicateTokenEx", wintypes.BOOL,
                       [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)])
CreateProcessAsUserW = _p(advapi32, "CreateProcessAsUserW", wintypes.BOOL,
                          [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR,
                           ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
                           wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                           ctypes.c_void_p, ctypes.c_void_p])

TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
MAXIMUM_ALLOWED = 0x2000000
SecurityImpersonation = 2
TokenPrimary = 1
TokenElevation = 20


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

EnableWindow = _p(user32, "EnableWindow", wintypes.BOOL, [wintypes.HWND, wintypes.BOOL])
InvalidateRect = _p(user32, "InvalidateRect", wintypes.BOOL,
                    [wintypes.HWND, ctypes.c_void_p, wintypes.BOOL])
SetWindowLongPtrW = _p(user32, "SetWindowLongPtrW", ctypes.c_longlong,
                      [wintypes.HWND, ctypes.c_int, ctypes.c_longlong])
CallWindowProcW = _p(user32, "CallWindowProcW", ctypes.c_longlong,
                     [ctypes.c_longlong, wintypes.HWND, wintypes.UINT,
                      wintypes.WPARAM, wintypes.LPARAM])
MessageBoxW = _p(user32, "MessageBoxW", ctypes.c_int,
                 [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT])
CreateFontIndirectW = _p(gdi32, "CreateFontIndirectW", wintypes.HANDLE, [ctypes.c_void_p])

# ---------------------------------------------------------------- GDI / uxtheme 绑定（莫奈自绘）
uxtheme = ctypes.WinDLL("uxtheme", use_last_error=True)
SetWindowTheme = _p(uxtheme, "SetWindowTheme", ctypes.c_long,
                   [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR])

BeginPaint = _p(user32, "BeginPaint", wintypes.HDC, [wintypes.HWND, ctypes.c_void_p])
EndPaint = _p(user32, "EndPaint", wintypes.BOOL, [wintypes.HWND, ctypes.c_void_p])
FillRect = _p(user32, "FillRect", wintypes.INT, [wintypes.HDC, ctypes.c_void_p, wintypes.HBRUSH])
RoundRect = _p(gdi32, "RoundRect", wintypes.BOOL,
               [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                ctypes.c_int, ctypes.c_int, ctypes.c_int])
TextOutW = _p(gdi32, "TextOutW", wintypes.BOOL,
              [wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.LPCWSTR, ctypes.c_int])
DrawTextW = _p(user32, "DrawTextW", wintypes.INT,
               [wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.UINT])
TrackMouseEvent = _p(user32, "TrackMouseEvent", wintypes.BOOL, [ctypes.c_void_p])

CreateSolidBrush = _p(gdi32, "CreateSolidBrush", wintypes.HBRUSH, [wintypes.COLORREF])
DeleteObject = _p(gdi32, "DeleteObject", wintypes.BOOL, [wintypes.HANDLE])
GetStockObject = _p(gdi32, "GetStockObject", wintypes.HANDLE, [ctypes.c_int])
SelectObject = _p(gdi32, "SelectObject", wintypes.HANDLE, [wintypes.HDC, wintypes.HANDLE])
SetBkMode = _p(gdi32, "SetBkMode", ctypes.c_int, [wintypes.HDC, ctypes.c_int])
SetBkColor = _p(gdi32, "SetBkColor", wintypes.COLORREF, [wintypes.HDC, wintypes.COLORREF])
SetTextColor = _p(gdi32, "SetTextColor", wintypes.COLORREF, [wintypes.HDC, wintypes.COLORREF])
CreatePen = _p(gdi32, "CreatePen", wintypes.HPEN, [ctypes.c_int, ctypes.c_int, wintypes.COLORREF])
MoveToEx = _p(gdi32, "MoveToEx", wintypes.BOOL,
              [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_void_p])
LineTo = _p(gdi32, "LineTo", wintypes.BOOL, [wintypes.HDC, ctypes.c_int, ctypes.c_int])
msimg32 = ctypes.WinDLL("msimg32", use_last_error=True)
GradientFill = _p(msimg32, "GradientFill", wintypes.BOOL,
                  [wintypes.HDC, ctypes.c_void_p, wintypes.ULONG,
                   ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG])


class PAINTSTRUCT(ctypes.Structure):
    _fields_ = [
        ("hdc", wintypes.HANDLE),
        ("fErase", wintypes.BOOL),
        ("rcPaint", RECT),
        ("fRestore", wintypes.BOOL),
        ("fIncUpdate", wintypes.BOOL),
        ("rgbReserved", wintypes.BYTE * 32),
    ]


class DRAWITEMSTRUCT(ctypes.Structure):
    _fields_ = [
        ("CtlType", wintypes.UINT),
        ("CtlID", wintypes.UINT),
        ("itemID", wintypes.UINT),
        ("itemAction", wintypes.UINT),
        ("itemState", wintypes.UINT),
        ("hwndItem", wintypes.HWND),
        ("hDC", wintypes.HANDLE),
        ("rcItem", RECT),
        ("itemData", ctypes.c_ulonglong),
    ]


class NMHDR(ctypes.Structure):
    _fields_ = [
        ("hwndFrom", wintypes.HWND),
        ("idFrom", ctypes.c_ulonglong),
        ("code", wintypes.UINT),
    ]


class NMCUSTOMDRAW(ctypes.Structure):
    _fields_ = [
        ("hdr", NMHDR),
        ("dwDrawStage", wintypes.DWORD),
        ("hdc", wintypes.HANDLE),
        ("rc", RECT),
        ("dwItemSpec", wintypes.DWORD),
        ("uItemState", wintypes.UINT),
        ("lItemlParam", wintypes.LPARAM),
    ]


class NMLVCUSTOMDRAW(ctypes.Structure):
    _fields_ = [
        ("nmcd", NMCUSTOMDRAW),
        ("clrText", wintypes.COLORREF),
        ("clrTextBk", wintypes.COLORREF),
        ("iSubItem", ctypes.c_int),
        ("dwItemType", wintypes.DWORD),
        ("clrFace", wintypes.COLORREF),
        ("iIconEffect", ctypes.c_int),
        ("iIconPhase", ctypes.c_int),
        ("iPartId", ctypes.c_int),
        ("iStateId", ctypes.c_int),
        ("rcText", RECT),
        ("uAlign", wintypes.UINT),
    ]


class TRIVERTEX(ctypes.Structure):
    _fields_ = [
        ("x", wintypes.LONG),
        ("y", wintypes.LONG),
        ("Red", ctypes.c_ushort),
        ("Green", ctypes.c_ushort),
        ("Blue", ctypes.c_ushort),
        ("Alpha", ctypes.c_ushort),
    ]


class GRADIENT_RECT(ctypes.Structure):
    _fields_ = [("UpperLeft", wintypes.ULONG), ("LowerRight", wintypes.ULONG)]


class TRACKMOUSEEVENT(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("hwndTrack", wintypes.HWND),
        ("dwHoverTime", wintypes.DWORD),
    ]

# 进程级消息过滤（放行跨完整性级别的拖放消息，Vista+ 已弃用但对提权窗口仍有效）
try:
    ChangeWindowMessageFilter = _p(user32, "ChangeWindowMessageFilter",
                                   wintypes.BOOL, [wintypes.UINT, wintypes.DWORD])
except Exception:  # noqa
    ChangeWindowMessageFilter = None

# 剪贴板（拖放被系统策略拦死时的兜底：资源管理器 Ctrl+C 后粘贴）
class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


ShellExecuteExW = _p(shell32, "ShellExecuteExW", wintypes.BOOL, [ctypes.c_void_p])
WaitForSingleObject = _p(kernel32, "WaitForSingleObject", wintypes.DWORD,
                         [wintypes.HANDLE, wintypes.DWORD])
GetExitCodeProcess = _p(kernel32, "GetExitCodeProcess", wintypes.BOOL,
                        [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)])
CloseHandle = _p(kernel32, "CloseHandle", wintypes.BOOL, [wintypes.HANDLE])
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
SW_HIDE = 0
ERROR_CANCELLED = 1223

OpenClipboard = _p(user32, "OpenClipboard", wintypes.BOOL, [wintypes.HWND])
CloseClipboard = _p(user32, "CloseClipboard", wintypes.BOOL, [])
GetClipboardData = _p(user32, "GetClipboardData", wintypes.HANDLE, [wintypes.UINT])
IsClipboardFormatAvailable = _p(user32, "IsClipboardFormatAvailable",
                                wintypes.BOOL, [wintypes.UINT])


# ---------------------------------------------------------------- IDropTarget
# 提权（管理员）窗口下，传统 WM_DROPFILES 通道会被 UIPI 拦截，光标显示为禁止图标。
# 通过实现 COM 的 IDropTarget 并用 RegisterDragDrop 注册到「主窗口 + 每个子控件」，
# 在 DragEnter/DragOver 中返回 DROPEFFECT_COPY，即可让光标变为「复制」并正常接收。
LPFN_QueryInterface = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p)
LPFN_AddRef = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)
LPFN_Release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)
LPFN_DragEnter = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p,
                                    wintypes.DWORD, POINTL,
                                    ctypes.POINTER(wintypes.DWORD))
LPFN_DragOver = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.DWORD,
                                   POINTL, ctypes.POINTER(wintypes.DWORD))
LPFN_DragLeave = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
LPFN_Drop = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p,
                               wintypes.DWORD, POINTL,
                               ctypes.POINTER(wintypes.DWORD))
# IDataObject::GetData 是虚表第 4 项（下标 3）
LPFN_GetData = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p,
                                  ctypes.POINTER(FORMATETC),
                                  ctypes.POINTER(STGMEDIUM))


class IDropTargetVtbl(ctypes.Structure):
    _fields_ = [
        ("QueryInterface", LPFN_QueryInterface),
        ("AddRef", LPFN_AddRef),
        ("Release", LPFN_Release),
        ("DragEnter", LPFN_DragEnter),
        ("DragOver", LPFN_DragOver),
        ("DragLeave", LPFN_DragLeave),
        ("Drop", LPFN_Drop),
    ]


class IDropTargetObj(ctypes.Structure):
    _fields_ = [("lpVtbl", ctypes.POINTER(IDropTargetVtbl))]


def _hdrop_paths(hdrop):
    """从 HDROP 句柄解析出全部路径。"""
    out = []
    if not hdrop:
        return out
    handle = wintypes.HANDLE(hdrop)
    count = DragQueryFileW(handle, 0xFFFFFFFF, None, 0)
    for i in range(count):
        n = DragQueryFileW(handle, i, None, 0)
        if n <= 0:
            continue
        buf = ctypes.create_unicode_buffer(n + 1)
        DragQueryFileW(handle, i, buf, n + 1)
        if buf.value:
            out.append(buf.value)
    return out


class DropTarget:
    """最小可用的 IDropTarget 实现（不做真正的引用计数生命周期管理，
    对象由 Python 侧持有，进程存活期间一直有效）。"""

    def __init__(self, on_files, on_enter=None, on_leave=None):
        self._on_files = on_files
        self._on_enter = on_enter
        self._on_leave = on_leave
        # 必须把回调对象保存为实例属性，否则会被 GC 回收导致崩溃
        self._cb = (
            LPFN_QueryInterface(self._query_interface),
            LPFN_AddRef(self._add_ref),
            LPFN_Release(self._release),
            LPFN_DragEnter(self._drag_enter),
            LPFN_DragOver(self._drag_over),
            LPFN_DragLeave(self._drag_leave),
            LPFN_Drop(self._drop),
        )
        self._vtbl = IDropTargetVtbl(*self._cb)
        self._obj = IDropTargetObj()
        self._obj.lpVtbl = ctypes.pointer(self._vtbl)
        self.ptr = ctypes.cast(ctypes.pointer(self._obj), ctypes.c_void_p)

    # --- IUnknown ---
    def _query_interface(self, this, riid, ppv):
        if ppv:
            ctypes.cast(ctypes.c_void_p(ppv),
                        ctypes.POINTER(ctypes.c_void_p))[0] = this
        return S_OK

    def _add_ref(self, this):
        return 2

    def _release(self, this):
        return 1

    # --- IDropTarget ---
    def _effect(self, pdw):
        if pdw:
            pdw[0] = DROPEFFECT_COPY
        return S_OK

    def _drag_enter(self, this, pDataObj, key, pt, pdw):
        if self._on_enter:
            try:
                self._on_enter()
            except Exception:  # noqa
                pass
        return self._effect(pdw)

    def _drag_over(self, this, key, pt, pdw):
        if self._on_enter:
            try:
                self._on_enter()
            except Exception:  # noqa
                pass
        return self._effect(pdw)

    def _drag_leave(self, this):
        if self._on_leave:
            try:
                self._on_leave()
            except Exception:  # noqa
                pass
        return S_OK

    def _drop(self, this, pDataObj, key, pt, pdw):
        if self._on_leave:
            try:
                self._on_leave()
            except Exception:  # noqa
                pass
        try:
            paths = self._extract(pDataObj)
            if paths:
                self._on_files(paths)
        except Exception:  # noqa
            pass
        if pdw:
            pdw[0] = DROPEFFECT_COPY
        return S_OK

    @staticmethod
    def _extract(pDataObj):
        """通过 IDataObject::GetData 取 CF_HDROP。"""
        if not pDataObj:
            return []
        obj = ctypes.c_void_p(pDataObj)
        vtbl = ctypes.cast(obj,
                           ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        get_data = LPFN_GetData(vtbl[3])
        fmt = FORMATETC(CF_HDROP, None, DVASPECT_CONTENT, -1, TYMED_HGLOBAL)
        med = STGMEDIUM()
        hr = get_data(pDataObj, ctypes.byref(fmt), ctypes.byref(med))
        if hr != S_OK:
            return []
        try:
            return _hdrop_paths(med.hGlobal)
        finally:
            try:
                ReleaseStgMedium(ctypes.byref(med))
            except Exception:  # noqa
                pass


# ---------------------------------------------------------------- 莫奈自绘：按钮悬停子类化（模块级）
def _split_rgb(rgb):
    """COLORREF(0xBBGGRR) -> 16 位 (r,g,b) 三元组，供 GradientFill 使用。"""
    r = rgb & 0xFF
    g = (rgb >> 8) & 0xFF
    b = (rgb >> 16) & 0xFF
    return (r << 8, g << 8, b << 8)


_BTN_SUBCLASS = {}   # hwnd -> (App, orig_wndproc)


def _btn_subclass_proc(hwnd, msg, wparam, lparam):
    app, orig = _BTN_SUBCLASS.get(hwnd, (None, None))
    if app is not None:
        if msg == WM_MOUSEMOVE:
            app._btn_hover(hwnd)
        elif msg == WM_MOUSELEAVE:
            app._btn_unhover(hwnd)
    if orig:
        return CallWindowProcW(orig, hwnd, msg, wparam, lparam)
    return DefWindowProcW(hwnd, msg, wparam, lparam)


_BTN_SUBCLASS_PROC = WNDPROC(_btn_subclass_proc)


# ---------------------------------------------------------------- 应用类
class App:
    def __init__(self):
        self.hwnd = None
        self.wndproc = WNDPROC(self._wndproc)
        self.targets = []          # 当前目标路径列表
        self.busy = False          # 是否有任务进行中
        self.cancel = threading.Event()
        self._log_text = ""        # 日志累积文本
        self._log_q = []
        self._prog_q = None
        self._results = None
        self._done = False
        self._controls = {}
        self._font_ui = None
        self._font_title = None
        self._child_wndproc = None
        self._subclasses = {}
        self._drop_target = None
        self._dd_windows = []
        self._ole_ok = False
        self._drag_over = False
        self._drag_timer = 0
        # 莫奈自绘状态
        self._od_kind = {}        # hwnd -> "btn" | "chk" | "grp"
        self._od_caption = {}     # hwnd -> 标题文字
        self._btn_orig = {}       # hwnd -> 原 wndproc（子类化用）
        self._hover_hwnd = None
        self._edit_brush = None
        self._list_header = None
        self._demote_failed = False   # 是否尝试过自降级但失败

    # ----------------------------------------------------- 字体
    def _make_font(self, size_pt, bold=False):
        lf = LOGFONTW()
        lf.lfHeight = -size_pt * 4 // 3      # 约等于 MulDiv(size, 96, 72)
        lf.lfWidth = 0
        lf.lfWeight = 700 if bold else 400
        lf.lfCharSet = 1                     # DEFAULT_CHARSET
        lf.lfQuality = 0                     # DEFAULT_QUALITY
        lf.lfPitchAndFamily = 0
        name = ctypes.create_unicode_buffer("Segoe UI")
        ctypes.memmove(lf.lfFaceName, name, ctypes.sizeof(name))
        return CreateFontIndirectW(ctypes.byref(lf))

    # ----------------------------------------------------- 入口
    def run(self):
        # 说明：早年用「自降级到中等完整性级别」来规避 UIPI 对拖放的拦截，
        # 但该方法在 UAC 关闭/管理员直接登录等环境下降级无效（子进程仍高权限），
        # 反而产生多余窗口。现改由「传统 WM_DROPFILES + ChangeWindowMessageFilter」
        # 通道承载跨权限拖放（UIPI 兼容），无需降级，标准/管理员模式均可拖入。

        # OLE 必须在建窗口之前、于 UI 线程初始化（RegisterDragDrop 依赖 STA）
        try:
            OleInitialize(None)
            self._ole_ok = True
        except Exception:  # noqa
            self._ole_ok = False

        # 进程级放行跨完整性级别的拖放消息（提权窗口接收普通资源管理器拖拽的前提）
        if ChangeWindowMessageFilter:
            for _m in (WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA):
                try:
                    ChangeWindowMessageFilter(_m, MSGFLT_ADD)
                except Exception:  # noqa
                    pass

        icc = INITCOMMONCONTROLSEX(dwSize=ctypes.sizeof(INITCOMMONCONTROLSEX),
                                   dwICC=ICC_PROGRESS_CLASS)
        InitCommonControlsEx(ctypes.byref(icc))

        hinst = GetModuleHandleW(None)
        cls = WNDCLASSEXW()
        cls.cbSize = ctypes.sizeof(WNDCLASSEXW)
        cls.style = 0
        cls.lpfnWndProc = ctypes.cast(self.wndproc, ctypes.c_void_p)
        cls.hInstance = hinst
        cls.hCursor = LoadCursorW(NULL, wintypes.LPCWSTR(IDC_ARROW))
        cls.lpszClassName = "FDFMainWindow"
        if not RegisterClassExW(ctypes.byref(cls)):
            raise ctypes.WinError(ctypes.get_last_error())

        self.hwnd = CreateWindowExW(
            0, "FDFMainWindow", "FDF · 强制删除工具",
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 1050, 750,
            NULL, NULL, hinst, None)
        if not self.hwnd:
            raise ctypes.WinError(ctypes.get_last_error())

        ShowWindow(self.hwnd, SW_SHOW)
        UpdateWindow(self.hwnd)
        SetTimer(self.hwnd, 1, 120, None)

        msg = MSG()
        while GetMessageW(ctypes.byref(msg), NULL, 0, 0) > 0:
            TranslateMessage(ctypes.byref(msg))
            DispatchMessageW(ctypes.byref(msg))

    # ----------------------------------------------------- 创建控件
    def _create_controls(self):
        h = self.hwnd
        hinst = GetModuleHandleW(None)
        self._font_ui = self._make_font(10)
        self._font_title = self._make_font(16, bold=True)
        SendMessageW(h, WM_SETFONT, wintypes.WPARAM(self._font_ui), 1)

        def ctrl(cls, text, x, y, w, hh, style, id_=0, font=None):
            hw = CreateWindowExW(0, cls, text,
                                 style | WS_CHILD | WS_VISIBLE,
                                 x, y, w, hh, h,
                                 wintypes.HMENU(id_), hinst, None)
            if font:
                SendMessageW(hw, WM_SETFONT, wintypes.WPARAM(font), 1)
            self._controls.setdefault("_all", []).append(hw)
            if style & BS_OWNERDRAW:
                self._od_caption[hw] = text
            return hw

        # 标题与副标题（加大字号、加宽区域）
        self._controls["title"] = ctrl(
            "STATIC", "FDF 强制删除工具",
            24, 16, 720, 34, SS_LEFT, 0, self._font_title)
        self._controls["subtitle"] = ctrl(
            "STATIC", "选择目标，绕过占用锁与权限限制进行强制删除 · 可直接拖入文件/文件夹 · 删除前将二次确认",
            24, 54, 960, 24, SS_LEFT, 0, self._font_ui)

        # 工具栏（自绘圆角粉彩按钮 — 加高到 38px，拉开间距）
        btn_y = 92
        btn_h = 38
        self._controls["add_file"] = ctrl("BUTTON", "添加文件",
                                          24, btn_y, 114, btn_h, BS_OWNERDRAW, ID_ADD_FILE, self._font_ui)
        self._controls["add_dir"] = ctrl("BUTTON", "添加文件夹",
                                         146, btn_y, 114, btn_h, BS_OWNERDRAW, ID_ADD_DIR, self._font_ui)
        self._controls["remove"] = ctrl("BUTTON", "移除选中",
                                        270, btn_y, 104, btn_h, BS_OWNERDRAW, ID_REMOVE, self._font_ui)
        self._controls["clear"] = ctrl("BUTTON", "清空",
                                       384, btn_y, 90, btn_h, BS_OWNERDRAW, ID_CLEAR, self._font_ui)
        self._controls["scan"] = ctrl("BUTTON", "扫描占用",
                                      486, btn_y, 114, btn_h, BS_OWNERDRAW, ID_SCAN, self._font_ui)
        self._controls["paste"] = ctrl("BUTTON", "粘贴路径",
                                       608, btn_y, 114, btn_h, BS_OWNERDRAW, ID_PASTE, self._font_ui)
        self._controls["delete"] = ctrl("BUTTON", "开始删除",
                                        840, 88, 178, 44, BS_OWNERDRAW, ID_DELETE, self._font_title)
        for key in ("add_file", "add_dir", "remove", "clear", "scan", "paste", "delete"):
            self._reg_od(self._controls[key], "btn")
            self._subclass_button(self._controls[key])

        # 选项分组框（原生控件 + 莫奈配色）
        grp_y = 146
        grp_h = 56
        chk_y = grp_y + 22
        chk_h = 26
        self._controls["grp_opt"] = ctrl("BUTTON", "删除模式",
                                         24, grp_y, 996, grp_h, SS_GROUPBOX, ID_GRP_OPT, self._font_ui)
        # 复选框（原生 BS_AUTOCHECKBOX + 莫奈配色）
        self._controls["chk_unlock"] = ctrl("BUTTON", "解锁占用句柄",
                                            42, chk_y, 230, chk_h, BS_AUTOCHECKBOX, ID_CHK_UNLOCK, self._font_ui)
        self._controls["chk_kill"] = ctrl("BUTTON", "结束占用进程",
                                          290, chk_y, 210, chk_h, BS_AUTOCHECKBOX, ID_CHK_KILL, self._font_ui)
        self._controls["chk_own"] = ctrl("BUTTON", "接管所有权",
                                         526, chk_y, 200, chk_h, BS_AUTOCHECKBOX, ID_CHK_OWN, self._font_ui)
        self._controls["chk_reboot"] = ctrl("BUTTON", "重启后删除",
                                          748, chk_y, 200, chk_h, BS_AUTOCHECKBOX, ID_CHK_REBOOT, self._font_ui)
        # 默认勾选（排除"结束占用进程"）
        for k in ("chk_unlock", "chk_own", "chk_reboot"):
            SendMessageW(self._controls[k], BM_SETCHECK, BST_CHECKED, 0)

        # ListView（目标列表 — 加宽加高）
        lv_style = LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER | WS_BORDER | WS_TABSTOP | WS_VSCROLL
        self._controls["list"] = ctrl(WC_LISTVIEWW, "",
                                      24, 216, 664, 400, lv_style, ID_LIST, self._font_ui)
        # 关闭 ListView 视觉主题，使自定义底色/文字色生效
        try:
            SetWindowTheme(self._controls["list"], "", "")
        except Exception:  # noqa
            pass
        self._init_listview()
        SendMessageW(self._controls["list"], LVM_SETBKCOLOR, 0, MONET_LIST_BG)
        SendMessageW(self._controls["list"], LVM_SETTEXTBKCOLOR, 0, -1)
        self._list_header = SendMessageW(self._controls["list"], LVM_GETHEADER, 0, 0)
        if self._list_header:
            try:
                SetWindowTheme(self._list_header, "", "")
            except Exception:  # noqa
                pass

        # 日志（加宽加高）
        log_x = 704
        self._controls["lbl_log"] = ctrl("STATIC", "操作日志",
                                         log_x, 216, 316, 20, SS_LEFT, ID_LBL_LOG, self._font_ui)
        self._controls["log"] = ctrl(
            "EDIT", "",
            log_x, 242, 316, 374,
            ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_BORDER | WS_VSCROLL | WS_TABSTOP,
            ID_LOG, self._font_ui)
        self._edit_brush = CreateSolidBrush(MONET_EDIT_BG)

        # 进度条与状态（进度条加高）
        prog_y = 632
        self._controls["progress"] = ctrl(
            PROGRESS_CLASSW, "",
            24, prog_y, 664, 22, WS_BORDER, ID_PROGRESS)
        SendMessageW(self._controls["progress"], PBM_SETRANGE, 0, (100 << 16) | 0)
        SendMessageW(self._controls["progress"], PBM_SETBARCOLOR, 0, MONET_PROG_BAR)
        SendMessageW(self._controls["progress"], PBM_SETBKCOLOR, 0, MONET_PROG_BG)
        self._controls["status"] = ctrl("STATIC", "就绪",
                                        24, 664, 996, 24, SS_LEFT, ID_STATUS, self._font_ui)

        # 窗口图标
        try:
            exe = sys.executable
            hicon = LoadImageW(NULL, wintypes.LPCWSTR(exe), IMAGE_ICON, 32, 32,
                               LR_LOADFROMFILE | LR_DEFAULTSIZE)
            if hicon:
                SendMessageW(h, WM_SETICON, ICON_BIG, wintypes.LPARAM(hicon))
                SendMessageW(h, WM_SETICON, ICON_SMALL, wintypes.LPARAM(hicon))
        except Exception:
            pass

        # 启用拖放（OLE IDropTarget 为主通道，WM_DROPFILES 为兜底）
        self._enable_dragdrop()

        self._log("FDF 强制删除工具已启动。", "info")
        if w.is_admin():
            self._log("当前以管理员身份运行：删除无需再次授权；"
                      "拖放与删除均正常工作。", "ok")
        else:
            self._log("当前为标准权限：可正常拖入文件/文件夹，"
                      "执行删除时会弹出一次 UAC 授权。", "ok")
        self._log("提示：删除前请确认目标无误；系统关键路径会被自动拦截。", "dim")

    # ----------------------------------------------------- ListView
    def _init_listview(self):
        lv = self._controls["list"]
        # 先插入列（宽度稍后由 _resize_list_columns 按实际控件宽度重算）
        cols = [("路径", 400), ("类型", 90), ("状态", 90)]
        for i, (name, width) in enumerate(cols):
            col = LVCOLUMNW()
            col.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT
            col.fmt = LVCFMT_LEFT
            col.cx = width
            buf = ctypes.create_unicode_buffer(name)
            col.pszText = ctypes.cast(buf, wintypes.LPWSTR)
            col.cchTextMax = len(name) + 1
            col.iSubItem = i
            lp = ctypes.cast(ctypes.byref(col), ctypes.c_void_p).value
            SendMessageW(lv, LVM_INSERTCOLUMNW, i, wintypes.LPARAM(lp))
        SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT,
                     LVS_EX_FULLROWSELECT)
        self._resize_list_columns()

    def _resize_list_columns(self):
        """根据 ListView 实际宽度按比例分配列宽。"""
        lv = self._controls.get("list")
        if not lv:
            return
        rc = RECT()
        GetClientRect(lv, ctypes.byref(rc))
        total_w = rc.right - rc.left
        if total_w <= 0:
            return
        # 减去边框/滚动条预留 (约 24px)
        avail = max(total_w - 24, 300)
        # 路径占 60%, 类型 18%, 状态 22%
        path_w = int(avail * 0.60)
        type_w = int(avail * 0.18)
        status_w = avail - path_w - type_w  # 剩余全给状态列
        SendMessageW(lv, LVM_SETCOLUMNWIDTH, 0, path_w)
        SendMessageW(lv, LVM_SETCOLUMNWIDTH, 1, type_w)
        SendMessageW(lv, LVM_SETCOLUMNWIDTH, 2, status_w)

    def _lv_set_item(self, index, subitem, text):
        lv = self._controls["list"]
        item = LVITEMW()
        item.mask = LVIF_TEXT
        item.iItem = index
        item.iSubItem = subitem
        buf = ctypes.create_unicode_buffer(text)
        item.pszText = ctypes.cast(buf, wintypes.LPWSTR)
        lp = ctypes.cast(ctypes.byref(item), ctypes.c_void_p).value
        if subitem == 0:
            SendMessageW(lv, LVM_INSERTITEMW, 0, wintypes.LPARAM(lp))
        else:
            SendMessageW(lv, LVM_SETITEMW, 0, wintypes.LPARAM(lp))

    # ----------------------------------------------------- 布局
    def _layout(self):
        r = RECT()
        GetClientRect(self.hwnd, ctypes.byref(r))
        cx, cy = r.right, r.bottom
        gap = 24
        flags = SWP_NOZORDER | SWP_NOACTIVATE

        def place(key, x, y, w, hh):
            c = self._controls.get(key)
            if c:
                SetWindowPos(c, NULL, x, y, w, hh, flags)

        # 标题/副标题（自适应宽度）
        place("title", gap, 16, cx - 2 * gap, 34)
        place("subtitle", gap, 54, cx - 2 * gap, 24)

        # 工具栏按钮（与创建时一致的尺寸）
        btn_y = 92
        btn_h = 38
        btn_w = 114
        del_w = 178
        del_h = 44
        place("add_file", gap, btn_y, btn_w, btn_h)
        place("add_dir", gap + btn_w + 8, btn_y, btn_w, btn_h)
        place("remove", gap + (btn_w + 8) * 2, btn_y, 104, btn_h)
        place("clear", gap + (btn_w + 8) * 3 + 4, btn_y, 90, btn_h)
        place("scan", gap + (btn_w + 8) * 4 + 4, btn_y, btn_w, btn_h)
        place("paste", gap + (btn_w + 8) * 5 + 4, btn_y, btn_w, btn_h)
        place("delete", cx - gap - del_w, 88, del_w, del_h)

        # 分组框 + 复选框
        grp_y = 146
        grp_h = 56
        chk_y = grp_y + 22
        chk_h = 26
        place("grp_opt", gap, grp_y, cx - 2 * gap, grp_h)
        place("chk_unlock", gap + 18, chk_y, 230, chk_h)
        place("chk_kill", gap + 266, chk_y, 210, chk_h)
        place("chk_own", gap + 502, chk_y, 200, chk_h)
        place("chk_reboot", gap + 728, chk_y, 200, chk_h)

        # 列表 + 日志（自适应比例）
        list_w = int((cx - 2 * gap) * 0.62)
        log_w = (cx - 2 * gap) - list_w - 14
        list_y = 216
        list_h = cy - list_y - 90   # 留出进度条+状态栏空间
        if list_h < 200:
            list_h = 200
        place("list", gap, list_y, list_w, list_h)
        place("lbl_log", gap + list_w + 14, list_y, log_w, 20)
        place("log", gap + list_w + 14, list_y + 24, log_w, max(list_h - 24, 160))
        place("progress", gap, cy - 66, list_w, 22)
        place("status", gap, cy - 38, cx - 2 * gap, 24)
        # 列宽随列表宽度自适应
        self._resize_list_columns()

    # ----------------------------------------------------- 日志/刷新
    def _log(self, msg, level="info"):
        self._log_q.append((msg, level))

    def _drain(self):
        if self._log_q:
            for msg, lvl in self._log_q:
                color = {"err": "✗", "warn": "!", "ok": "✓", "step": "»",
                         "dim": "·"}.get(lvl, "·")
                self._log_text += f"[{color}] {msg}\r\n"
            self._log_q.clear()
            c = self._controls.get("log")
            if c:
                SetWindowTextW(c, self._log_text)
                SendMessageW(c, EM_SETSEL, 0x7FFFFFFF, 0x7FFFFFFF)
                SendMessageW(c, EM_SCROLLCARET, 0, 0)
        if self._prog_q is not None:
            SendMessageW(self._controls["progress"], PBM_SETPOS,
                         wintypes.WPARAM(self._prog_q), 0)
            self._prog_q = None
        if self._done and self._results is not None:
            self._refresh_list(self._results)
            self._results = None
            self._done = False
            self.busy = False
            self._set_buttons_enabled(True)
            self._update_status("操作完成。")

    # ----------------------------------------------------- 列表
    def _refresh_list(self, results=None):
        lv = self._controls["list"]
        SendMessageW(lv, LVM_DELETEALLITEMS, 0, 0)
        for i, path in enumerate(self.targets):
            typ = "文件夹" if os.path.isdir(path) else "文件"
            status = ""
            if results:
                rr = results.get(path)
                st = getattr(rr, "status", None) if rr else None
                status = {"deleted": "已删除", "reboot": "待重启",
                          "failed": "失败", "missing": "不存在",
                          "blocked": "已拦截"}.get(st, "")
            self._lv_set_item(i, 0, path)
            self._lv_set_item(i, 1, typ)
            self._lv_set_item(i, 2, status)

    def _add_target(self, path):
        ap = os.path.abspath(path)
        if ap.lower() in [t.lower() for t in self.targets]:
            return
        if not w.path_exists(ap):
            self._log(f"路径不存在，已忽略：{ap}", "err")
            return
        self.targets.append(ap)
        self._refresh_list()
        self._log(f"已添加：{ap}", "dim")

    # ----------------------------------------------------- 按钮状态
    def _set_buttons_enabled(self, enabled):
        for k in ("add_file", "add_dir", "remove", "clear", "scan", "paste", "delete"):
            c = self._controls.get(k)
            if c:
                EnableWindow(c, 1 if enabled else 0)

    def _update_status(self, text):
        SetWindowTextW(self._controls["status"], text)

    # ----------------------------------------------------- 对话框
    def _pick_files(self):
        buf = ctypes.create_unicode_buffer(65536)
        ofn = OPENFILENAMEW()
        ofn.lStructSize = ctypes.sizeof(OPENFILENAMEW)
        ofn.hwndOwner = self.hwnd
        ofn.lpstrFilter = "所有文件\0*.*\0"
        ofn.lpstrFile = ctypes.cast(buf, wintypes.LPWSTR)
        ofn.nMaxFile = 65536
        ofn.Flags = 0x00080000 | 0x00000200  # OFN_EXPLORER | OFN_ALLOWMULTISELECT
        ofn.lpstrTitle = "选择要删除的文件"
        if GetOpenFileNameW(ctypes.byref(ofn)):
            text = buf.value
            if "\0" in text:
                parts = [p for p in text.split("\0") if p]
                if len(parts) > 1:
                    base = parts[0]
                    for name in parts[1:]:
                        self._add_target(os.path.join(base, name))
                elif parts:
                    self._add_target(parts[0])
            elif text:
                self._add_target(text)

    def _pick_dir(self):
        buf = ctypes.create_unicode_buffer(1024)
        bi = BROWSEINFOW()
        bi.hwndOwner = self.hwnd
        bi.lpszTitle = "选择要删除的文件夹"
        bi.ulFlags = 0x0001 | 0x0040  # BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE
        pidl = SHBrowseForFolderW(ctypes.byref(bi))
        if pidl:
            if SHGetPathFromIDListW(pidl, buf):
                self._add_target(buf.value)
            CoTaskMemFree(pidl)

    # ----------------------------------------------------- 拖放
    def _all_windows(self):
        """主窗口 + 全部子控件句柄（去掉 _controls 里的辅助列表项）。"""
        out = [self.hwnd]
        for hw in self._controls.get("_all", []):
            if hw and hw not in out:
                out.append(hw)
        return out

    def _enable_dragdrop(self):
        try:
            self._enable_dragdrop_impl()
        except Exception as _e:  # noqa
            import traceback as _tb
            raise

    def _enable_dragdrop_impl(self):
        wins = self._all_windows()
        elevated = _is_elevated()

        # 1) 窗口级放行跨完整性级别的拖放消息（UIPI 兼容的前提）
        if ChangeWindowMessageFilterEx:
            for hw in wins:
                for m in (WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA):
                    try:
                        ChangeWindowMessageFilterEx(hw, m, MSGFLT_ALLOW, None)
                    except Exception:  # noqa
                        pass

        # 2) 通道选择
        #    标准权限：OLE IDropTarget 体验更好（悬停高亮、命中任意子控件）。
        #    高权限（管理员）：OLE 拖放在 UIPI 下会被「静默拦截」——它本质是 COM
        #    调用，不受 ChangeWindowMessageFilter 保护；注册能成功，但真正拖入时
        #    被系统丢弃。只有传统 WM_DROPFILES 通道在 ChangeWindowMessageFilter
        #    (MSFLT_ADD) 放行后可跨完整性级别工作。因此高权限下只走 WM_DROPFILES。
        use_ole = self._ole_ok and not elevated
        ok = 0
        if use_ole:
            try:
                if self._drop_target is None:
                    self._drop_target = DropTarget(self._on_drop_paths,
                                                   on_enter=self._drag_highlight_on,
                                                   on_leave=self._drag_highlight_off)
                for hw in wins:
                    try:
                        RevokeDragDrop(hw)      # 清掉 shell 可能已注册的目标
                    except Exception:  # noqa
                        pass
                    try:
                        hr = RegisterDragDrop(hw, self._drop_target.ptr)
                    except Exception:  # noqa
                        hr = -1
                    if hr == S_OK:
                        ok += 1
                        self._dd_windows.append(hw)
            except Exception as e:  # noqa
                self._log(f"OLE 拖放初始化异常：{e}", "warn")
        else:
            # 高权限或 OLE 不可用：使用 UIPI 兼容的传统 WM_DROPFILES 通道。
            self._enable_legacy_drop(wins)

        if use_ole:
            self._log(f"拖放已就绪（OLE 通道，{ok} 个区域）。", "dim")
        else:
            self._log("拖放已就绪（兼容通道，支持从资源管理器跨权限拖入）。", "dim")
        self._log("可直接拖入文件/文件夹；若拖放无效，请改用「粘贴路径」按钮。", "dim")

    def _enable_legacy_drop(self, windows):
        try:
            if self._child_wndproc is None:
                self._child_wndproc = WNDPROC(self._child_proc)
            proc_ptr = ctypes.cast(self._child_wndproc, ctypes.c_void_p).value
        except Exception:  # noqa
            return
        for hwnd in windows:
            if not hwnd:
                continue
            try:
                DragAcceptFiles(hwnd, True)
            except Exception:  # noqa
                pass
            if hwnd == self.hwnd:
                continue                     # 主窗口自己的 WndProc 已处理
            try:
                old = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, proc_ptr)
                if old:
                    self._subclasses[hwnd] = old
            except Exception:  # noqa
                pass

    def _on_drop_paths(self, paths):
        """OLE 拖放回调（运行在 UI 线程）。"""
        if self.busy:
            self._log("正在处理任务，已忽略本次拖入。", "warn")
            return
        n = 0
        for p in paths:
            if p:
                self._add_target(p)
                n += 1
        if n:
            self._log(f"已从拖放添加 {n} 个项目。", "ok")

    # ----------------------------------------------------- 拖放高亮反馈
    def _drag_highlight_on(self):
        """拖拽悬停在窗口上方时调用：高亮目标区域 + 提示文字。"""
        if self._drag_timer:
            KillTimer(self.hwnd, 2)
            self._drag_timer = 0
        if not self._drag_over:
            self._drag_over = True
            self._paint_highlight(True)
        self._update_status("松开鼠标即可添加文件 / 文件夹…")

    def _drag_highlight_off(self):
        """拖拽离开窗口时调用：延迟一点关闭高亮，避免在子控件之间移动时闪烁。"""
        if self.hwnd and not self._drag_timer:
            self._drag_timer = SetTimer(self.hwnd, 2, 120, None)

    def _drag_highlight_off_now(self):
        self._drag_over = False
        self._drag_timer = 0
        self._paint_highlight(False)
        self._update_status("就绪。")

    def _paint_highlight(self, on):
        lv = self._controls.get("list")
        if not lv:
            return
        # 莫奈高亮：淡紫；恢复：列表底色
        col = MONET_LIST_HL if on else MONET_LIST_BG
        SendMessageW(lv, LVM_SETBKCOLOR, 0, col)
        SendMessageW(lv, LVM_SETTEXTBKCOLOR, 0, MONET_LIST_HL if on else -1)
        InvalidateRect(lv, None, True)

    # ----------------------------------------------------- 剪贴板兜底
    def _paste_from_clipboard(self):
        if self.busy:
            return
        paths = []
        try:
            if not OpenClipboard(self.hwnd):
                self._log("无法打开剪贴板。", "err")
                return
            try:
                if IsClipboardFormatAvailable(CF_HDROP):
                    paths = _hdrop_paths(GetClipboardData(CF_HDROP))
                elif IsClipboardFormatAvailable(CF_UNICODETEXT):
                    h = GetClipboardData(CF_UNICODETEXT)
                    ptr = GlobalLock(h)
                    if ptr:
                        try:
                            text = ctypes.wstring_at(ptr)
                        finally:
                            GlobalUnlock(h)
                        for line in text.replace("\r", "\n").split("\n"):
                            line = line.strip().strip('"')
                            if line:
                                paths.append(line)
            finally:
                CloseClipboard()
        except Exception as e:  # noqa
            self._log(f"读取剪贴板失败：{e}", "err")
            return
        if not paths:
            self._log("剪贴板中没有文件或路径（可在资源管理器里选中后 Ctrl+C）。", "warn")
            return
        for p in paths:
            self._add_target(p)
        self._log(f"已从剪贴板添加 {len(paths)} 个项目。", "ok")

    def _child_proc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_DROPFILES:
                # HDROP 在 wParam，转发给主窗口统一处理
                SendMessageW(self.hwnd, WM_DROPFILES,
                             wintypes.WPARAM(wparam), wintypes.LPARAM(0))
                return 0
        except Exception:
            pass
        old = self._subclasses.get(hwnd)
        if old:
            return CallWindowProcW(old, hwnd, msg, wparam, lparam)
        return DefWindowProcW(hwnd, msg, wparam, lparam)

    def _on_drop(self, hdrop):
        """兼容通道：WM_DROPFILES。"""
        try:
            paths = _hdrop_paths(hdrop)
        except Exception:  # noqa
            paths = []
        try:
            DragFinish(wintypes.HANDLE(hdrop))
        except Exception:  # noqa
            pass
        if not paths:
            self._log("收到拖放，但未解析到文件（可能被系统拦截，或源无文件）。", "warn")
            return
        self._on_drop_paths(paths)

    def _remove_selected(self):
        lv = self._controls["list"]
        idx = SendMessageW(lv, LVM_GETNEXTITEM, -1, LVNI_SELECTED)
        if idx < 0:
            return
        if 0 <= idx < len(self.targets):
            removed = self.targets.pop(idx)
            self._refresh_list()
            self._log(f"已移除：{removed}", "dim")

    # ----------------------------------------------------- 后台任务
    def _run_worker(self, kind):
        self.busy = True
        self.cancel.clear()
        self._set_buttons_enabled(False)
        self._update_status("正在处理…")
        try:
            if w.is_admin():
                self._run_inprocess(kind)
            else:
                self._run_elevated(kind)
        except Exception:  # noqa
            import traceback
            self._log(f"执行出错：{traceback.format_exc()}", "err")
        finally:
            self._done = True
            self._prog_q = 0

    def _options(self):
        return Options(
            unlock_handles=self._checked("chk_unlock"),
            kill_processes=self._checked("chk_kill"),
            take_ownership=self._checked("chk_own"),
            schedule_reboot=self._checked("chk_reboot"),
        )

    def _run_inprocess(self, kind):
        d = ForceDeleter(
            self._options(),
            log=lambda m, l="info": self._log(m, l),
            progress=lambda done, total, s="": self._progress(done, total),
            cancel=self.cancel,
        )
        if kind == "scan":
            procs = d.scan(self.targets)
            if procs:
                self._log(f"发现 {len(procs)} 个进程可能占用目标：", "warn")
                for p in procs:
                    self._log(f"  · {p['name']} (PID {p['pid']}) — 涉及 {p['count']} 个文件", "dim")
            else:
                self._log("未发现占用目标文件的进程。", "ok")
        else:
            results = d.delete(self.targets)
            self._results = {r.path: r for r in results}

    # ---------------------------------------------- 提权子进程（UAC）
    def _run_elevated(self, kind):
        """当前是普通权限：拉起提权的 --worker 子进程执行，实时回显其输出。

        界面之所以不直接以管理员运行，是因为 Windows 的 UIPI 会禁止
        资源管理器向提权窗口拖放文件（光标显示禁止图标）。
        """
        import json
        import tempfile
        import uuid

        tag = uuid.uuid4().hex[:12]
        tmp = tempfile.gettempdir()
        job_path = os.path.join(tmp, f"fdf_job_{tag}.json")
        out_path = os.path.join(tmp, f"fdf_out_{tag}.jsonl")
        cancel_path = os.path.join(tmp, f"fdf_cancel_{tag}.flag")
        o = self._options()
        job = {
            "kind": kind,
            "targets": list(self.targets),
            "out": out_path,
            "cancel": cancel_path,
            "options": {
                "unlock_handles": o.unlock_handles,
                "kill_processes": o.kill_processes,
                "take_ownership": o.take_ownership,
                "schedule_reboot": o.schedule_reboot,
            },
        }
        with open(job_path, "w", encoding="utf-8") as f:
            json.dump(job, f, ensure_ascii=False)
        open(out_path, "w", encoding="utf-8").close()

        exe = sys.executable
        args = f'--worker "{job_path}"'
        # 以脚本方式运行时（未打包），需要 python.exe main.py --worker
        if not getattr(sys, "frozen", False):
            script = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))), "main.py")
            args = f'"{script}" --worker "{job_path}"'

        self._log("正在请求管理员权限…（请在 UAC 弹窗中点「是」）", "step")

        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
        sei.hwnd = self.hwnd
        sei.lpVerb = "runas"
        sei.lpFile = exe
        sei.lpParameters = args
        sei.lpDirectory = os.path.dirname(exe)
        sei.nShow = SW_HIDE
        ctypes.set_last_error(0)
        if not ShellExecuteExW(ctypes.byref(sei)):
            err = ctypes.get_last_error()
            if err == ERROR_CANCELLED:
                self._log("已取消提权，操作未执行。", "warn")
            else:
                self._log(f"无法启动提权进程（错误码 {err}）。", "err")
            self._cleanup_job(job_path, out_path, cancel_path)
            return

        hproc = sei.hProcess
        self._log("已获得管理员权限，开始执行。", "ok")
        try:
            self._pump_worker(out_path, cancel_path, hproc)
        finally:
            try:
                CloseHandle(hproc)
            except Exception:  # noqa
                pass
            self._cleanup_job(job_path, out_path, cancel_path)

    def _pump_worker(self, out_path, cancel_path, hproc):
        """轮询工作进程的 JSONL 输出并转成界面事件。"""
        import json
        import time

        procs = []
        results = {}
        pos = 0
        ended = False
        while True:
            if self.cancel.is_set() and not os.path.exists(cancel_path):
                try:
                    open(cancel_path, "w").close()
                except Exception:  # noqa
                    pass
            try:
                with open(out_path, "r", encoding="utf-8") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
            except Exception:  # noqa
                chunk = ""
            for line in chunk.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:  # noqa
                    continue
                t = ev.get("t")
                if t == "log":
                    self._log(ev.get("m", ""), ev.get("l", "info"))
                elif t == "prog":
                    self._progress(ev.get("d", 0), ev.get("n", 0))
                elif t == "proc":
                    procs.append(ev)
                elif t == "res":
                    r = ItemResult(
                        path=ev.get("path", ""), status=ev.get("status", ""),
                        detail=ev.get("detail", ""), files=ev.get("files", 0),
                        folders=ev.get("folders", 0), bytes=ev.get("bytes", 0))
                    results[r.path] = r
                elif t == "end":
                    ended = True
            if ended:
                break
            # 进程已退出且没有新内容 → 收尾
            if WaitForSingleObject(hproc, 0) == 0 and not chunk:
                time.sleep(0.2)
                try:
                    if os.path.getsize(out_path) <= pos:
                        break
                except Exception:  # noqa
                    break
                continue
            time.sleep(0.15)

        if procs:
            self._log(f"发现 {len(procs)} 个进程可能占用目标：", "warn")
            for p in procs:
                self._log(f"  · {p.get('name')} (PID {p.get('pid')}) — 涉及 {p.get('count')} 个文件", "dim")
        elif not results and not ended:
            self._log("工作进程异常结束，未收到结果。", "err")
        if results:
            self._results = results

    @staticmethod
    def _cleanup_job(*paths):
        for p in paths:
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except Exception:  # noqa
                pass

    def _progress(self, done, total):
        if total and total > 0:
            self._prog_q = int(done * 100 / total)

    def _checked(self, key):
        return SendMessageW(self._controls[key], BM_GETCHECK, 0, 0) == BST_CHECKED

    # ----------------------------------------------------- 莫奈自绘
    def _reg_od(self, hw, kind):
        self._od_kind[hw] = kind

    def _subclass_button(self, hw):
        orig = SetWindowLongPtrW(
            hw, GWLP_WNDPROC,
            ctypes.cast(_BTN_SUBCLASS_PROC, ctypes.c_void_p).value)
        self._btn_orig[hw] = orig
        _BTN_SUBCLASS[hw] = (self, orig)

    def _btn_hover(self, hwnd):
        if self._hover_hwnd != hwnd:
            old = self._hover_hwnd
            self._hover_hwnd = hwnd
            if old:
                InvalidateRect(old, None, True)
            InvalidateRect(hwnd, None, True)
        tme = TRACKMOUSEEVENT()
        tme.cbSize = ctypes.sizeof(TRACKMOUSEEVENT)
        tme.dwFlags = 0x2            # TME_LEAVE
        tme.hwndTrack = hwnd
        tme.dwHoverTime = 0
        TrackMouseEvent(ctypes.byref(tme))

    def _btn_unhover(self, hwnd):
        if self._hover_hwnd == hwnd:
            self._hover_hwnd = None
            InvalidateRect(hwnd, None, True)

    # ---- 背景渐变
    def _paint_gradient(self, hdc, hwnd):
        rc = RECT()
        GetClientRect(hwnd, ctypes.byref(rc))
        vt = (TRIVERTEX * 2)()
        r0, g0, b0 = _split_rgb(MONET_TOP_BG)
        r1, g1, b1 = _split_rgb(MONET_BOTTOM_BG)
        vt[0].x = rc.left
        vt[0].y = rc.top
        vt[0].Red, vt[0].Green, vt[0].Blue = r0, g0, b0
        vt[1].x = rc.right
        vt[1].y = rc.bottom
        vt[1].Red, vt[1].Green, vt[1].Blue = r1, g1, b1
        gr = GRADIENT_RECT()
        gr.UpperLeft = 0
        gr.LowerRight = 1
        GradientFill(hdc, ctypes.byref(vt[0]), 2,
                     ctypes.byref(gr), 1, GRADIENT_FILL_RECT_V)

    def _on_paint(self, hwnd):
        ps = PAINTSTRUCT()
        hdc = BeginPaint(hwnd, ctypes.byref(ps))
        self._paint_gradient(hdc, hwnd)
        EndPaint(hwnd, ctypes.byref(ps))
        return 0

    # ---- 自绘分发
    def _on_drawitem(self, lparam):
        dis = ctypes.cast(lparam, ctypes.POINTER(DRAWITEMSTRUCT)).contents
        kind = self._od_kind.get(dis.hwndItem)
        if kind == "btn":
            self._draw_button(dis)
        elif kind == "chk":
            self._draw_checkbox(dis)
        elif kind == "grp":
            self._draw_groupbox(dis)
        return 1

    def _fill_round(self, hdc, rc, fill, border, radius=12):
        hbr = CreateSolidBrush(fill)
        hpen = CreatePen(PS_SOLID, 1, border)
        old_br = SelectObject(hdc, hbr)
        old_pen = SelectObject(hdc, hpen)
        RoundRect(hdc, rc.left + 1, rc.top + 1, rc.right - 1, rc.bottom - 1,
                  radius * 2, radius * 2)
        SelectObject(hdc, old_pen)
        SelectObject(hdc, old_br)
        DeleteObject(hpen)
        DeleteObject(hbr)

    def _draw_button(self, dis):
        hdc = wintypes.HDC(dis.hDC)
        rc = dis.rcItem
        is_del = (dis.hwndItem == self._controls.get("delete"))
        hovered = (dis.hwndItem == self._hover_hwnd)
        pressed = bool(dis.itemState & ODS_SELECTED)
        if is_del:
            face = MONET_DEL_PRESS if pressed else (
                MONET_DEL_HOVER if hovered else MONET_DEL_FACE)
            border = MONET_DEL_BORDER
        else:
            face = MONET_BTN_PRESS if pressed else (
                MONET_BTN_HOVER if hovered else MONET_BTN_FACE)
            border = MONET_BTN_BORDER
        old_font = SelectObject(hdc, self._font_title if is_del else self._font_ui)
        self._fill_round(hdc, rc, face, border, 9)
        SetBkMode(hdc, TRANSPARENT)
        SetTextColor(hdc, MONET_TITLE if is_del else MONET_TEXT)
        dx = dy = 1 if pressed else 0
        r = RECT(rc.left + dx, rc.top + dy, rc.right + dx, rc.bottom + dy)
        DrawTextW(hdc, self._od_caption.get(dis.hwndItem, ""), -1,
                  ctypes.byref(r), 0x00000025)   # DT_CENTER|DT_VCENTER|DT_SINGLELINE
        if old_font:
            SelectObject(hdc, old_font)

    def _draw_checkbox(self, dis):
        hdc = wintypes.HDC(dis.hDC)
        rc = dis.rcItem
        box = 18
        bx = rc.left + 2
        by = rc.top + (rc.bottom - rc.top - box) // 2
        checked = bool(SendMessageW(dis.hwndItem, BM_GETCHECK, 0, 0) & BST_CHECKED)
        hbr = CreateSolidBrush(MONET_WARMPINK if checked else MONET_CREAM)
        hpen = CreatePen(PS_SOLID, 1, MONET_BTN_BORDER)
        old_br = SelectObject(hdc, hbr)
        old_pen = SelectObject(hdc, hpen)
        RoundRect(hdc, bx, by, bx + box, by + box, 6, 6)
        SelectObject(hdc, old_pen)
        SelectObject(hdc, old_br)
        DeleteObject(hpen)
        DeleteObject(hbr)
        if checked:
            pen = CreatePen(PS_SOLID, 2, MONET_TITLE)
            op = SelectObject(hdc, pen)
            MoveToEx(hdc, bx + 3, by + box // 2, None)
            LineTo(hdc, bx + box // 2 - 1, by + box - 4)
            LineTo(hdc, bx + box - 3, by + 4)
            SelectObject(hdc, op)
            DeleteObject(pen)
        old_font = SelectObject(hdc, self._font_ui)
        SetBkMode(hdc, TRANSPARENT)
        SetTextColor(hdc, MONET_TEXT)
        tx = RECT(bx + box + 6, rc.top, rc.right, rc.bottom)
        DrawTextW(hdc, self._od_caption.get(dis.hwndItem, ""), -1,
                  ctypes.byref(tx), 0x00000024)   # DT_VCENTER|DT_SINGLELINE|DT_LEFT
        if old_font:
            SelectObject(hdc, old_font)

    def _draw_groupbox(self, dis):
        hdc = wintypes.HDC(dis.hDC)
        rc = dis.rcItem
        hpen = CreatePen(PS_SOLID, 1, MONET_LILAC)
        old_pen = SelectObject(hdc, hpen)
        RoundRect(hdc, rc.left + 1, rc.top + 1, rc.right - 1, rc.bottom - 1, 14, 14)
        SelectObject(hdc, old_pen)
        DeleteObject(hpen)
        # 标题：用顶部渐变色遮住边框线后再写文字，保证无缝
        cap = self._od_caption.get(dis.hwndItem, "")
        old_font = SelectObject(hdc, self._font_ui)
        SetBkMode(hdc, OPAQUE)
        SetBkColor(hdc, MONET_TOP_BG)
        SetTextColor(hdc, MONET_TITLE)
        cr = RECT(rc.left + 12, rc.top, rc.left + 12 + 220, rc.top + 20)
        DrawTextW(hdc, cap, -1, ctypes.byref(cr), 0x00000000)   # DT_LEFT
        if old_font:
            SelectObject(hdc, old_font)

    # ---- ListView / 表头 自绘（统一文字与底色）
    def _on_notify(self, lparam):
        nm = ctypes.cast(lparam, ctypes.POINTER(NMHDR)).contents
        if nm.code != NM_CUSTOMDRAW:
            return 0
        lv = self._controls.get("list")
        hdr = self._list_header
        if nm.hwndFrom == lv and lv:
            cd = ctypes.cast(lparam, ctypes.POINTER(NMLVCUSTOMDRAW)).contents
            if cd.nmcd.dwDrawStage == CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW
            if cd.nmcd.dwDrawStage == CDDS_ITEMPREPAINT:
                cd.clrText = MONET_TEXT
                cd.clrTextBk = MONET_LIST_HL if self._drag_over else MONET_LIST_BG
                return CDRF_NEWFONT
        elif nm.hwndFrom == hdr and hdr:
            cd = ctypes.cast(lparam, ctypes.POINTER(NMCUSTOMDRAW)).contents
            if cd.dwDrawStage == CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW
            if cd.dwDrawStage == CDDS_ITEMPREPAINT:
                cd.clrText = MONET_TEXT
                cd.clrTextBk = MONET_HDR_BG
                return CDRF_NEWFONT
        return CDRF_DODEFAULT

    # ----------------------------------------------------- 窗口过程
    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_CREATE:
                self.hwnd = hwnd
                self._create_controls()
                self._layout()
                return 0
            if msg == WM_GETMINMAXINFO:
                mmi = ctypes.cast(lparam, ctypes.POINTER(MINMAXINFO)).contents
                mmi.ptMinTrackSize.x = 900
                mmi.ptMinTrackSize.y = 680
                return 0
            if msg == WM_SIZE:
                self._layout()
                return 0
            if msg == WM_TIMER:
                if wparam == 2:
                    self._drag_highlight_off_now()
                    return 0
                self._drain()
                return 0
            if msg == WM_DROPFILES:
                self._on_drop(int(wparam))     # HDROP 在 wParam
                return 0
            if msg == WM_PAINT:
                return self._on_paint(hwnd)
            if msg == WM_ERASEBKGND:
                self._paint_gradient(wintypes.HDC(wparam), hwnd)
                return 1
            if msg == WM_CTLCOLORSTATIC:
                hdc = wintypes.HDC(wparam)
                SetBkMode(hdc, TRANSPARENT)
                if lparam in (self._controls.get("title", 0),
                              self._controls.get("subtitle", 0)):
                    SetTextColor(hdc, MONET_TITLE)
                else:
                    SetTextColor(hdc, MONET_TEXT)
                return int(GetStockObject(NULL_BRUSH))
            if msg == WM_CTLCOLOREDIT:
                if not self._edit_brush:
                    return 0
                hdc = wintypes.HDC(wparam)
                SetBkMode(hdc, OPAQUE)
                SetBkColor(hdc, MONET_EDIT_BG)
                SetTextColor(hdc, MONET_TEXT)
                return int(self._edit_brush)
            if msg == WM_DRAWITEM:
                return self._on_drawitem(lparam)
            if msg == WM_NOTIFY:
                return self._on_notify(lparam)
            if msg == WM_COMMAND:
                cid = wparam & 0xFFFF
                return self._on_command(cid)
            if msg == WM_DESTROY:
                KillTimer(hwnd, 1)
                for hw in self._dd_windows:
                    try:
                        RevokeDragDrop(hw)
                    except Exception:  # noqa
                        pass
                self._dd_windows = []
                if self._ole_ok:
                    try:
                        OleUninitialize()
                    except Exception:  # noqa
                        pass
                if self._edit_brush:
                    try:
                        DeleteObject(self._edit_brush)
                    except Exception:  # noqa
                        pass
                    self._edit_brush = None
                PostQuitMessage(0)
                return 0
        except Exception:  # noqa: 窗口过程绝不能因未处理异常而崩溃
            import traceback
            try:
                _tb = traceback.format_exc()
                self._log("WndProc 异常: " + _tb, "err")
            except Exception:
                pass
            return 0
        return DefWindowProcW(hwnd, msg, wparam, lparam)

    def _on_command(self, cid):
        if self.busy:
            return 0
        if cid == ID_ADD_FILE:
            self._pick_files()
        elif cid == ID_ADD_DIR:
            self._pick_dir()
        elif cid == ID_REMOVE:
            self._remove_selected()
        elif cid == ID_PASTE:
            self._paste_from_clipboard()
        elif cid == ID_CLEAR:
            self.targets.clear()
            self._refresh_list()
            self._log("已清空目标列表。", "dim")
        elif cid == ID_SCAN:
            if not self.targets:
                self._log("请先添加要扫描的目标。", "warn")
                return 0
            threading.Thread(target=self._run_worker, args=("scan",), daemon=True).start()
        elif cid == ID_DELETE:
            if not self.targets:
                self._log("请先添加要删除的目标。", "warn")
                return 0
            if not self._confirm_delete():
                return 0
            threading.Thread(target=self._run_worker, args=("delete",), daemon=True).start()
        return 0

    def _confirm_delete(self):
        n = len(self.targets)
        res = MessageBoxW(
            self.hwnd,
            f"确定要强制删除选中的 {n} 个项目吗？\n此操作不可撤销，请确认目标无误。",
            "确认删除", 0x00000004 | 0x00000030)  # MB_YESNO | MB_ICONEXCLAMATION
        return res == 6  # IDYES


def main():
    app = App()
    app.run()


if __name__ == "__main__":
    main()
