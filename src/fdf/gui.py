"""FDF 强制删除工具 — 图形界面（PySide6，Windows 11 Fluent 风格）。

完全替代原 ctypes 手绘界面与莫奈粉彩 PySide6 版，保留原有全部功能与交互逻辑：
  · 从资源管理器拖入文件/文件夹（Qt 原生拖放）
  · 文件 / 文件夹选择对话框、剪贴板粘贴路径补全
  · 删除选项（强制关闭占用句柄 / 结束占用进程 / 接管所有权 / 重启时删除）
  · 删除 / 扫描：双进程模型（普通权限 UI + 提权 worker 子进程弹 UAC）
  · 实时日志、进度条、结果回显
  · Windows 11 Fluent Design 风格：白色底、#0078D4 蓝色强调、卡片式布局、
    现代扁平按钮、toggle 风格复选框、高 DPI 适配、响应式布局

注意：本模块仅在 GUI 模式被导入（main.py 在 --worker 模式下提前 sys.exit，
不会加载 Qt），因此不影响提权子进程的轻量启动。
"""
import os
import sys
import json
import time
import uuid
import threading
import ctypes
from ctypes import wintypes

from fdf import winapi as w
from fdf.engine import ForceDeleter, Options, ItemResult

# ---------------------------------------------------------------------------
# Windows 11 Fluent 配色
# ---------------------------------------------------------------------------
F = {
    "bg":           "#F3F3F3",   # 页面底色（浅灰）
    "card":         "#FFFFFF",    # 卡片/面板底色（纯白）
    "ink":          "#1A1A1A",    # 主文字（近黑）
    "ink_secondary":"#5C5C5C",   # 次要文字（中灰）
    "ink_tertiary": "#8A8A8A",   # 辅助文字（浅灰）
    "accent":       "#0078D4",   # Windows 蓝强调色
    "accent_hover": "#106EBE",   # 蓝悬停
    "accent_light": "#DEECF9",   # 蓝浅底（选中/高亮）
    "danger":       "#D13438",   # 危险红（删除按钮）
    "danger_hover": "#A4262C",   # 红悬停
    "danger_light": "#FDE7E9",   # 红浅底
    "border":       "#E0E0E0",   # 卡片边框
    "border_focus": "#0078D4",   # 聚焦边框
    "ok":           "#107C10",   # 成功绿
    "ok_light":     "#DFF6DD",   # 成功浅底
    "warn":         "#C23918",   # 警告橙红
    "warn_light":   "#FED9CC",   # 警告浅底
    "err":          "#D13438",   # 错误红
    "err_light":    "#FDE7E9",   # 错误浅底
    "scrollbar":    "#CFCFCF",   # 滚动条
    "divider":      "#EAEAEA",   # 分割线
}

# 控件 ID（沿用原命令分发逻辑）
ID_ADD_FILE, ID_ADD_DIR, ID_REMOVE, ID_PASTE, ID_CLEAR, ID_SCAN, ID_DELETE, \
    ID_CANCEL = range(1001, 1009)

# ---------------------------------------------------------------------------
# 提权相关 ctypes（仅用于 UAC 拉起 worker 子进程，其余 UI 全由 Qt 接管）
# 用 WinDLL(use_last_error=True) 而非 windll：ctypes.get_last_error() 才能取到
# ShellExecuteExW 失败时的真实错误码（如 UAC 取消 ERROR_CANCELLED=1223）。
# ---------------------------------------------------------------------------
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


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
        ("hKeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", ctypes.c_void_p),
        ("hProcess", wintypes.HANDLE),
    ]


SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
SEE_MASK_NO_CONSOLE = 0x00008000   # 防止 worker 弹出控制台窗口
SW_HIDE = 0
ERROR_CANCELLED = 1223

_SEI_FUNC = _shell32.ShellExecuteExW
_SEI_FUNC.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
_SEI_FUNC.restype = wintypes.BOOL

# 句柄 / 等待相关 API：显式声明 argtypes，避免 64 位句柄按默认 c_int 截断
_kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_kernel32.WaitForSingleObject.restype = wintypes.DWORD
_kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
_kernel32.TerminateProcess.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL


def _runas(exe, params, hwnd=0):
    """以管理员权限启动 exe，返回 (hProcess, last_error)。失败返回 (None, err)。"""
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_NO_CONSOLE
    sei.hwnd = hwnd
    sei.lpVerb = "runas"
    sei.lpFile = exe
    sei.lpParameters = params
    sei.lpDirectory = os.path.dirname(exe)
    sei.nShow = SW_HIDE
    ctypes.set_last_error(0)
    if not _SEI_FUNC(ctypes.byref(sei)):
        return None, ctypes.get_last_error()
    return sei.hProcess, 0


def _is_elevated():
    try:
        advapi32 = ctypes.windll.advapi32
        tok = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
            return False

        class _TE(ctypes.Structure):
            _fields_ = [("TokenIsElevated", wintypes.DWORD)]

        te = _TE()
        sz = wintypes.DWORD()
        advapi32.GetTokenInformation(tok, 20, ctypes.byref(te),
                                     ctypes.sizeof(te), ctypes.byref(sz))
        _kernel32.CloseHandle(tok)
        return bool(te.TokenIsElevated)
    except Exception:
        return False


def _split_clipboard_paths(text):
    """把剪贴板文本拆成路径列表：按行拆分；单行内支持空格分隔与引号包裹。

    Windows 路径含反斜杠，不能用 shlex 的 posix 转义语义，这里用简单
    状态机：仅在引号外把空白当分隔符，成对引号包裹含空格的路径。
    """
    paths = []
    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        if '"' not in line and not any(c.isspace() for c in line):
            paths.append(line)
            continue
        cur = []
        quoted = False
        for ch in line:
            if ch == '"':
                quoted = not quoted
            elif ch.isspace() and not quoted:
                if cur:
                    paths.append("".join(cur))
                    cur = []
            else:
                cur.append(ch)
        if cur:
            paths.append("".join(cur))
    return paths


# ---------------------------------------------------------------------------
# Qt 导入（仅 GUI 模式会执行到本模块；worker 模式不 import）
# ---------------------------------------------------------------------------
from PySide6.QtCore import Qt, QObject, Signal
from PySide6.QtGui import QFont, QColor, QDragEnterEvent, QDropEvent, QIcon
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QCheckBox,
    QListWidget, QListWidgetItem, QProgressBar, QPlainTextEdit, QFileDialog,
    QMessageBox, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
    QSizePolicy, QGraphicsDropShadowEffect, QAbstractItemView, QDialog,
)


class _Bus(QObject):
    """跨线程 UI 更新信号桥（queued 连接，自动回到主线程执行）。"""
    log = Signal(str, str)
    progress = Signal(int)
    status = Signal(str)
    enabled = Signal(bool)
    results = Signal(object)
    busy = Signal(bool)


class App:
    """业务逻辑层：持有状态、后端删除引擎调用、双进程提权模型。"""

    def __init__(self):
        self.targets = []
        self.busy = False
        self.cancel = threading.Event()
        self._results = None
        self._bus = _Bus()
        self.win = None
        self._qapp = None
        self._worker_thread = None   # 当前工作线程（退出窗口时带超时 join）
        self._cancel_path = None     # 提权任务的 cancel 文件（取消/退出时写入）
        self._job_files = ()         # 提权任务的临时文件（退出时兜底清理）

    # ===================================================================
    # 入口
    # ===================================================================
    def run(self):
        # 高 DPI 取整策略必须在 QApplication 构造之前设置（构造后再调用是 no-op）
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
        self._qapp = QApplication(sys.argv)
        self._qapp.setStyle("Fusion")
        self.win = MainWindow(self)
        # 全局样式表：所有 Qt 对话框（含 QFileDialog）自动继承 Fluent 风格，
        # 避免独立顶层窗口回退到 Windows 原生外观。
        self._qapp.setStyleSheet(_fluent_qss())
        self.win.resize(1100, 760)
        self.win.setMinimumSize(920, 700)
        self.win.show()
        self._log("FDF 强制删除工具已启动。", "info")
        if _is_elevated():
            self._log("当前以管理员身份运行：删除无需再次授权。", "warn")
        else:
            self._log("当前为标准权限：拖入文件后，删除时会弹出一次 UAC 授权。", "ok")
        self._log("提示：删除前请确认目标无误；系统关键路径会被自动拦截。", "dim")
        sys.exit(self._qapp.exec())

    # ===================================================================
    # UI 更新（线程安全：经信号回到主线程）
    # ===================================================================
    def _log(self, msg, level="info"):
        self._bus.log.emit(msg, level)

    def _update_status(self, text):
        self._bus.status.emit(text)

    def _set_buttons_enabled(self, enabled):
        self._bus.enabled.emit(bool(enabled))

    def _progress(self, done, total):
        pct = int(done * 100 / total) if total and total > 0 else 0
        self._bus.progress.emit(pct)

    def _refresh_list(self, results=None):
        self._bus.results.emit(results)

    # ===================================================================
    # 业务：目标管理
    # ===================================================================
    def _add_target(self, path):
        """把路径加入目标列表，成功入列返回 True（重复/不存在返回 False）。"""
        ap = os.path.abspath(path)
        if any(ap.lower() == t.lower() for t in self.targets):
            return False
        if not w.path_exists(ap):
            self._log(f"路径不存在，已忽略：{ap}", "err")
            return False
        self.targets.append(ap)
        self._refresh_list()
        self._log(f"已添加：{ap}", "dim")
        return True

    def _remove_selected(self, index):
        if index < 0 or index >= len(self.targets):
            return
        removed = self.targets.pop(index)
        self._refresh_list()
        self._log(f"已移除：{removed}", "dim")

    def _clear_targets(self):
        self.targets.clear()
        self._refresh_list()
        self._log("已清空目标列表。", "dim")

    def _on_drop_paths(self, paths):
        if self.busy:
            self._log("正在处理任务，已忽略本次拖入。", "warn")
            return
        n = sum(1 for p in paths if p and self._add_target(p))
        if n:
            self._log(f"已从拖放添加 {n} 个项目。", "ok")
        else:
            self._log("没有新项目被添加（重复或路径不存在）。", "warn")

    def _paste_from_clipboard(self):
        if self.busy:
            return
        try:
            mime = QApplication.clipboard().mimeData()
            paths = []
            if mime.hasUrls():
                for u in mime.urls():
                    if u.isLocalFile():
                        paths.append(u.toLocalFile())
            elif mime.hasText():
                paths = _split_clipboard_paths(mime.text())
        except Exception as e:
            self._log(f"读取剪贴板失败：{e}", "err")
            return
        if not paths:
            self._log("剪贴板中没有文件或路径（可在资源管理器选中后 Ctrl+C）。", "warn")
            return
        n = sum(1 for p in paths if self._add_target(p))
        if n:
            self._log(f"已从剪贴板添加 {n} 个项目。", "ok")
        else:
            self._log("剪贴板中的路径均未入列（重复或不存在）。", "warn")

    # ===================================================================
    # 业务：选择对话框
    # ===================================================================
    def _pick_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self.win, "选择要删除的文件", "", "所有文件 (*.*)",
            options=QFileDialog.Option.DontUseNativeDialog)
        for f in files:
            self._add_target(f)

    def _pick_dir(self):
        d = QFileDialog.getExistingDirectory(
            self.win, "选择要删除的文件夹",
            options=QFileDialog.Option.DontUseNativeDialog
            | QFileDialog.Option.ShowDirsOnly)
        if d:
            self._add_target(d)

    def _confirm_delete(self):
        n = len(self.targets)
        return _show_confirm(
            self.win,
            "确认删除",
            f"即将强制删除列表中的全部 {n} 个项目（无论是否选中）。\n此操作不可撤销，请确认目标无误。")

    # ===================================================================
    # 命令分发
    # ===================================================================
    def _on_command(self, cid):
        if cid == ID_CANCEL:
            # 取消仅在任务进行中有效：请求中止后等现有流程自然收尾
            if self.busy:
                self.request_cancel()
                self._log("已请求取消，等待当前操作中止…", "warn")
            return
        if self.busy:
            return
        if cid == ID_ADD_FILE:
            self._pick_files()
        elif cid == ID_ADD_DIR:
            self._pick_dir()
        elif cid == ID_REMOVE:
            self.win.remove_current()
        elif cid == ID_PASTE:
            self._paste_from_clipboard()
        elif cid == ID_CLEAR:
            self._clear_targets()
        elif cid == ID_SCAN:
            if not self.targets:
                self._log("请先添加要扫描的目标。", "warn")
                return
            self._start_worker("scan")
        elif cid == ID_DELETE:
            if not self.targets:
                self._log("请先添加要删除的目标。", "warn")
                return
            if not self._confirm_delete():
                return
            self._start_worker("delete")

    # ===================================================================
    # 业务：删除 / 扫描（双进程模型）
    # ===================================================================
    def _options(self):
        return Options(
            unlock_handles=self.win.chk_unlock.isChecked(),
            kill_processes=self.win.chk_kill.isChecked(),
            take_ownership=self.win.chk_own.isChecked(),
            schedule_reboot=self.win.chk_reboot.isChecked(),
            shred=self.win.chk_shred.isChecked(),
        )

    def _start_worker(self, kind):
        """在主线程内取好 Qt 状态快照并启动工作线程。

        · options 快照与窗口句柄都在主线程读取，工作线程不再触碰任何
          Qt 对象（QCheckBox.isChecked / winId 均非线程安全）；
        · busy 在 start() 之前置位，避免快速双击并发拉起两个提权 worker。
        """
        if self.busy:
            return
        self.busy = True
        options = self._options()
        hwnd = int(self.win.winId()) if self.win else 0
        self._worker_thread = threading.Thread(
            target=self._run_worker, args=(kind, options, hwnd), daemon=True)
        self._worker_thread.start()

    def request_cancel(self):
        """请求中止当前任务：置取消事件，并向提权 worker 写 cancel 文件。"""
        self.cancel.set()
        cp = self._cancel_path
        if cp and not os.path.exists(cp):
            try:
                open(cp, "w").close()
            except Exception as e:
                self._log(f"写入取消标记失败：{e}", "warn")

    def _run_worker(self, kind, options, hwnd):
        self.cancel.clear()
        self._bus.enabled.emit(False)
        self._bus.busy.emit(True)
        self._bus.progress.emit(0)   # 重置进度条，避免显示上一轮的 100%
        self._update_status("正在处理…")
        try:
            if _is_elevated():
                self._run_inprocess(kind, options)
            else:
                self._run_elevated(kind, options, hwnd)
        except Exception:
            import traceback
            self._log("执行出错：" + traceback.format_exc(), "err")
        finally:
            self.busy = False
            self._bus.enabled.emit(True)
            self._bus.busy.emit(False)
            self._update_status("操作完成。")

    def _run_inprocess(self, kind, options):
        d = ForceDeleter(
            options,
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
            self._bus.results.emit(self._results)

    def _run_elevated(self, kind, options, hwnd):
        """普通权限：拉起提权的 --worker 子进程执行，实时回显其输出。"""
        import tempfile
        tag = uuid.uuid4().hex[:12]
        tmp = tempfile.gettempdir()
        job_path = os.path.join(tmp, f"fdf_job_{tag}.json")
        out_path = os.path.join(tmp, f"fdf_out_{tag}.jsonl")
        cancel_path = os.path.join(tmp, f"fdf_cancel_{tag}.flag")
        # 记录到实例上，供「取消」按钮与窗口关闭时的收尾逻辑使用
        self._cancel_path = cancel_path
        self._job_files = (job_path, out_path, cancel_path)
        job = {
            "kind": kind,
            "targets": list(self.targets),
            "out": out_path,
            "cancel": cancel_path,
            "options": {
                "unlock_handles": options.unlock_handles,
                "kill_processes": options.kill_processes,
                "take_ownership": options.take_ownership,
                "schedule_reboot": options.schedule_reboot,
                "shred": options.shred,
            },
        }
        with open(job_path, "w", encoding="utf-8") as f:
            json.dump(job, f, ensure_ascii=False)
        open(out_path, "w", encoding="utf-8").close()

        exe = sys.executable
        args = f'--worker "{job_path}"'
        if not getattr(sys, "frozen", False):
            script = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__)))), "main.py")
            args = f'"{script}" --worker "{job_path}"'

        self._log("正在请求管理员权限…（请在 UAC 弹窗中点「是」）", "step")

        hproc, err = _runas(exe, args, hwnd=hwnd)
        if hproc is None:
            if err == ERROR_CANCELLED:
                self._log("已取消提权，操作未执行。", "warn")
            else:
                self._log(f"无法启动提权进程（错误码 {err}）。", "err")
            self._finish_job(job_path, out_path, cancel_path, hproc=None)
            return

        self._log("已获得管理员权限，开始执行。", "ok")
        try:
            self._pump_worker(out_path, cancel_path, hproc)
        finally:
            self._finish_job(job_path, out_path, cancel_path, hproc=hproc)

    def _finish_job(self, job_path, out_path, cancel_path, hproc=None):
        """收尾：等 worker 进程退出、关句柄、清理临时文件并复位任务状态。"""
        try:
            if hproc is not None:
                # 先等进程真正退出再删临时文件，避免其仍占用 job/out 文件
                if _kernel32.WaitForSingleObject(hproc, 5000) != 0:
                    self._log("等待工作进程退出超时，仍尝试清理临时文件。", "warn")
                _kernel32.CloseHandle(hproc)
        except Exception:
            pass
        self._cleanup_job(job_path, out_path, cancel_path)
        self._cancel_path = None
        self._job_files = ()

    def _pump_worker(self, out_path, cancel_path, hproc):
        """轮询工作进程的 JSONL 输出并转成界面事件。"""
        import time as _time
        procs = []
        results = {}
        pos = 0
        ended = False
        _start = _time.time()
        _TIMEOUT = 600.0   # 单次操作最长等待 10 分钟

        def handle_line(line):
            nonlocal ended
            line = line.strip()
            if not line:
                return
            try:
                ev = json.loads(line)
            except Exception:
                return
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

        while True:
            # ---- 超时保护：优先写 cancel 文件请求 worker 自行退出，
            #      TerminateProcess 仅作最后手段 ----
            if _time.time() - _start > _TIMEOUT:
                self._log(f"操作超时（{_TIMEOUT:.0f}秒），正在请求工作进程中止…", "err")
                try:
                    if not os.path.exists(cancel_path):
                        open(cancel_path, "w").close()
                except Exception:
                    pass
                if _kernel32.WaitForSingleObject(hproc, 5000) != 0:
                    self._log("工作进程未响应取消请求，强制结束进程。", "err")
                    if not _kernel32.TerminateProcess(hproc, 1):
                        self._log(
                            f"强制结束工作进程失败（错误码 {ctypes.get_last_error()}）。",
                            "err")
                break

            if self.cancel.is_set() and not os.path.exists(cancel_path):
                try:
                    open(cancel_path, "w").close()
                except Exception:
                    pass
            # ---- 尾随读取：二进制模式（seek/tell 为精确字节偏移），
            #      只处理以换行结尾的完整行，pos 仅推进到最后一个换行符处，
            #      写入中途的残行留待下轮重读，避免半行被当成整行吞掉 ----
            try:
                with open(out_path, "rb") as f:
                    f.seek(pos)
                    chunk = f.read()
            except Exception:
                chunk = b""
            last_nl = chunk.rfind(b"\n")
            if last_nl >= 0:
                for raw in chunk[:last_nl + 1].split(b"\n"):
                    handle_line(raw.decode("utf-8", "replace"))
                pos += last_nl + 1
            if ended:
                break
            if _kernel32.WaitForSingleObject(hproc, 0) == 0:
                # 进程已退出：稍候最后的输出落盘，终读一次后收尾
                time.sleep(0.2)
                try:
                    with open(out_path, "rb") as f:
                        f.seek(pos)
                        tail = f.read()
                    for raw in tail.split(b"\n"):
                        handle_line(raw.decode("utf-8", "replace"))
                except Exception:
                    pass
                break
            time.sleep(0.15)

        if procs:
            self._log(f"发现 {len(procs)} 个进程可能占用目标：", "warn")
            for p in procs:
                self._log(f"  · {p.get('name')} (PID {p.get('pid')}) — 涉及 {p.get('count')} 个文件", "dim")
        elif not results and not ended:
            self._log("工作进程异常结束，未收到结果。", "err")
        if results:
            self._results = results
            self._bus.results.emit(results)

    def _cleanup_job(self, *paths):
        """删除任务临时文件；短超时重试，失败时记录日志而不是静默吞掉。"""
        for p in paths:
            if not p:
                continue
            for attempt in range(5):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                    break
                except Exception as e:
                    if attempt == 4:
                        self._log(f"清理临时文件失败：{p}（{e}）", "warn")
                    time.sleep(0.1)


# ===========================================================================
# Fluent 风格对话框（替代原生 QMessageBox，避免 Windows 暗色主题）
# ===========================================================================

def _show_confirm(parent, title: str, message: str) -> bool:
    """显示 Fluent 风格的 Yes/No 确认对话框，返回 True=Yes。"""
    dlg = _ConfirmDialog(parent, title, message)
    return dlg.exec() == QDialog.DialogCode.Accepted


class _ConfirmDialog(QDialog):
    """自定义确认对话框：白底、Fluent 配色、圆角，不受 Windows 暗色主题影响。"""

    def __init__(self, parent, title: str, message: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setObjectName("fluentDialog")
        self.setFixedSize(420, 180)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.CustomizeWindowHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        # 关键：显式设置样式表（QDialog 是独立顶层窗口，不继承父窗口样式）
        self.setStyleSheet(_fluent_qss())

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        # 内容区
        body = QWidget()
        body.setObjectName("dialogBody")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(28, 24, 28, 16)
        bl.setSpacing(16)

        # 图标 + 文字行
        row = QHBoxLayout()
        row.setSpacing(14)

        icon_lbl = QLabel("\u2753")   # ❓
        icon_lbl.setObjectName("dialogIcon")
        row.addWidget(icon_lbl)

        msg_lbl = QLabel(message)
        msg_lbl.setObjectName("dialogMessage")
        msg_lbl.setWordWrap(True)
        row.addWidget(msg_lbl, 1)

        bl.addLayout(row)

        # 按钮行
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_row.addStretch(1)

        self._btn_no = QPushButton("No")
        self._btn_no.setObjectName("dialogBtnNo")
        self._btn_no.setFixedWidth(80)
        self._btn_no.setFixedHeight(32)
        self._btn_no.clicked.connect(self.reject)
        btn_row.addWidget(self._btn_no)

        self._btn_yes = QPushButton("Yes")
        self._btn_yes.setObjectName("dialogBtnYes")
        self._btn_yes.setFixedWidth(80)
        self._btn_yes.setFixedHeight(32)
        self._btn_yes.setDefault(True)
        self._btn_yes.clicked.connect(self.accept)
        btn_row.addWidget(self._btn_yes)

        bl.addLayout(btn_row)
        vl.addWidget(body)


def _show_warning(parent, title: str, message: str):
    """显示 Fluent 风格的警告/错误提示对话框（仅「确定」按钮）。"""
    dlg = _WarnDialog(parent, title, message)
    dlg.exec()


class _WarnDialog(QDialog):
    """警告 / 错误提示对话框（单按钮）。"""

    def __init__(self, parent, title: str, message: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setObjectName("fluentDialog")
        self.setFixedSize(420, 160)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.CustomizeWindowHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        # 显式设置样式表（独立顶层窗口）
        self.setStyleSheet(_fluent_qss())

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)

        body = QWidget()
        body.setObjectName("dialogBody")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(28, 24, 28, 16)
        bl.setSpacing(16)

        row = QHBoxLayout()
        row.setSpacing(14)

        icon_lbl = ("\u26A0" if "Warning" in title or "警告" in title
                    else "\u2717")   # ⚠ 或 ✗
        ic = QLabel(icon_lbl)
        ic.setObjectName("dialogIconWarn" if "Warning" in title or "警告" in title
                        else "dialogIconErr")
        row.addWidget(ic)

        msg_lbl = QLabel(message)
        msg_lbl.setObjectName("dialogMessage")
        msg_lbl.setWordWrap(True)
        row.addWidget(msg_lbl, 1)
        bl.addLayout(row)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        ok_btn = QPushButton("确定")
        ok_btn.setObjectName("dialogBtnYes")
        ok_btn.setFixedWidth(80)
        ok_btn.setFixedHeight(32)
        ok_btn.clicked.connect(self.accept)
        btn_row.addWidget(ok_btn)
        bl.addLayout(btn_row)

        vl.addWidget(body)


# ===========================================================================
# 主窗口（PySide6 — Windows 11 Fluent 风格）
# ===========================================================================

class _CheckButton(QCheckBox):
    """自绘复选框：用 QPainter 直接绘制方框和对勾。

    Windows 上 QCheckBox 的 ::indicator 常被系统主题吞掉导致方框不可见。
    本类重写 paintEvent 用 QPainter 直接绘制，保证方框始终可见且样式一致。
    """
    _BOX_SIZE = 18          # 方框边长
    _BOX_RADIUS = 4         # 圆角半径
    _BORDER_WIDTH = 2       # 边框粗细
    _TEXT_OFFSET = 10       # 方框与文字间距

    # 配色（从 F 字典运行时读取）
    _c_border = "#E0E0E0"
    _c_bg     = "#FFFFFF"
    _c_accent = "#0078D4"
    _c_check  = "#FFFFFF"
    _c_text   = "#1A1A1A"
    _c_text_checked = "#0078D4"

    def __init__(self, text: str):
        super().__init__(text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

    def paintEvent(self, event):
        from PySide6.QtGui import (QPainter, QPen, QBrush, QColor,
                                    QFont, QFontMetrics)
        from PySide6.QtCore import QRect, Qt, QPointF

        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        h = self.height()
        box = self._BOX_SIZE
        br = self._BORDER_WIDTH
        # 方框垂直居中
        bx = 0
        by = (h - box) // 2
        rect = QRect(bx, by, box, box).adjusted(0, 0, -1, -1)

        # ---- 绘制方框 ----
        if self.isChecked():
            p.setBrush(QBrush(QColor(self._c_accent)))
            p.setPen(QPen(QColor(self._c_accent), br))
        else:
            p.setBrush(QBrush(QColor(self._c_bg)))
            p.setPen(QPen(QColor(self._c_border), br))
        p.drawRoundedRect(rect, self._BOX_RADIUS, self._BOX_RADIUS)

        # ---- 选中时绘制白色对勾 ----
        if self.isChecked():
            check_pen = QPen(QColor(self._c_check), 2.5)
            check_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            check_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            p.setPen(check_pen)
            # 对勾三段折线，全部在 18×18 方框内
            #   起点(左下) → 拐点(中下) → 终点(右上)
            pt1 = QPointF(bx + 4.0, by + 9.5)    # 左下
            pt2 = QPointF(bx + 8.0, by + 13.5)    # 中下拐角
            pt3 = QPointF(bx + 14.0, by + 5.0)     # 右上
            p.drawLine(pt1, pt2)
            p.drawLine(pt2, pt3)

        # ---- 绘制文字（含 emoji 图标）----
        tx = box + self._TEXT_OFFSET
        tw = self.width() - tx - 4
        trect = QRect(tx, 0, tw, h)
        p.setPen(QPen(QColor(self._c_text_checked if self.isChecked() else self._c_text)))
        p.setFont(self.font())
        flags = Qt.AlignmentFlag.AlignVCenter | Qt.TextFlag.TextSingleLine
        p.drawText(trect, flags, self.text())

        p.end()


class MainWindow(QWidget):
    def __init__(self, app: App):
        super().__init__()
        self.app = app
        self.setWindowTitle("FDF — 强制删除文件工具")
        self._build_ui()
        self.setAcceptDrops(True)
        self._connect_signals()

    # -------------------------------------------------------------- 构建
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ===== 标题栏区域（类 PowerToys 顶栏）=====
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(52)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(28, 0, 20, 0)
        title_icon = QLabel("\u2605")   # 星形图标占位
        title_icon.setObjectName("titleIcon")
        title_text = QLabel("FDF  强制删除文件工具")
        title_text.setObjectName("titleText")
        hl.addWidget(title_icon)
        hl.addWidget(title_text)
        hl.addStretch(1)
        root.addWidget(header)

        # ===== 主内容区（可滚动）=====
        content = QWidget()
        content.setObjectName("mainContent")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(28, 24, 28, 20)
        cl.setSpacing(20)

        # --- 目标文件卡片 ---
        target_card = _Card("目标文件", "将文件或文件夹拖入下方列表，或使用按钮添加。")
        tl = target_card.body_layout

        # 列表
        self.list = QListWidget()
        self.list.setObjectName("targetList")
        self.list.setAlternatingRowColors(True)
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.list.setAcceptDrops(False)
        self.list.setMinimumHeight(160)
        self.list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        tl.addWidget(self.list, 1)

        # 列表下方操作按钮行
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self._target_btns = []   # 目标管理按钮，busy 期间一并禁用
        for text, cid in [
            ("\uD83D\uDCC1  添加文件", ID_ADD_FILE),
            ("\uD83D\uDCC2  添加文件夹", ID_ADD_DIR),
            ("\u2716  移除选中", ID_REMOVE),
            ("\uD83D\uDCCB  粘贴路径", ID_PASTE),
            ("\uD83D\uDDD1  清空", ID_CLEAR),
        ]:
            b = QPushButton(text)
            b.setObjectName("btnSecondary")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda checked, c=cid: self.app._on_command(c))
            btn_row.addWidget(b)
            self._target_btns.append(b)
        btn_row.addStretch(1)
        tl.addLayout(btn_row)

        cl.addWidget(target_card)

        # --- 选项卡片 ---
        opt_card = _Card("删除选项", "配置强制删除的行为策略。")
        ol = opt_card.body_layout
        og = QGridLayout()
        og.setVerticalSpacing(12)
        og.setHorizontalSpacing(24)

        # 用 checkable QPushButton 替代 QCheckBox：
        # Windows 上 QCheckBox 的 ::indicator 常被系统主题吞掉导致方框不可见，
        # 而 QPushButton 的 :checked 伪状态 + QSS 完全可控。
        self.chk_unlock = _CheckButton("\uD83D\uDD12  强制关闭占用句柄")
        self.chk_kill = _CheckButton("\u2699\uFE0F  结束占用进程")
        self.chk_own = _CheckButton("\uD83D\uDC51  接管所有权与权限")
        self.chk_reboot = _CheckButton("\uD83D\uDD04  重启时删除（兜底）")
        self.chk_shred = _CheckButton("\uD83D\uDD25  删除前粉碎覆写")
        self.chk_unlock.setChecked(True)
        self.chk_own.setChecked(True)
        self.chk_reboot.setChecked(True)

        og.addWidget(self.chk_unlock, 0, 0)
        og.addWidget(self.chk_kill, 0, 1)
        og.addWidget(self.chk_own, 1, 0)
        og.addWidget(self.chk_reboot, 1, 1)
        og.addWidget(self.chk_shred, 2, 0)
        ol.addLayout(og)

        cl.addWidget(opt_card)

        # --- 操作 + 日志卡片（左右分栏）---
        action_log = QHBoxLayout()
        action_log.setSpacing(20)

        # 左侧：操作按钮
        act_card = _Card("执行操作", "")
        al = act_card.body_layout
        act_btn_row = QHBoxLayout()
        act_btn_row.setSpacing(10)

        self.btn_scan = QPushButton("\uD83D\uDD0D  扫描占用")
        self.btn_scan.setObjectName("btnPrimary")
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.clicked.connect(lambda: self.app._on_command(ID_SCAN))

        self.btn_delete = QPushButton("\u2714  开始删除")
        self.btn_delete.setObjectName("btnDanger")
        self.btn_delete.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_delete.clicked.connect(lambda: self.app._on_command(ID_DELETE))

        # 取消按钮：仅任务进行中（busy）可用，点击后请求 worker 中止
        self.btn_cancel = QPushButton("\u23F9  取消")
        self.btn_cancel.setObjectName("btnSecondary")
        self.btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(lambda: self.app._on_command(ID_CANCEL))

        act_btn_row.addWidget(self.btn_scan)
        act_btn_row.addWidget(self.btn_delete)
        act_btn_row.addWidget(self.btn_cancel)
        act_btn_row.addStretch(1)
        al.addLayout(act_btn_row)

        # 进度条
        self.progress = QProgressBar()
        self.progress.setObjectName("fluentProgress")
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setFixedHeight(22)
        al.addWidget(self.progress)

        # 状态标签
        self.status = QLabel("就绪 — 拖入文件或点击添加开始使用")
        self.status.setObjectName("statusLabel")
        al.addWidget(self.status)

        action_log.addWidget(act_card, 1)

        # 右侧：日志
        log_card = _Card("运行日志", "")
        ll = log_card.body_layout
        self.log = QPlainTextEdit()
        self.log.setObjectName("logArea")
        self.log.setReadOnly(True)
        self.log.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        ll.addWidget(self.log, 1)
        action_log.addWidget(log_card, 2)

        cl.addLayout(action_log, 1)

        root.addWidget(content, 1)

    def _connect_signals(self):
        b = self.app._bus
        b.log.connect(self.append_log)
        b.progress.connect(self.set_progress)
        b.status.connect(self.set_status)
        b.enabled.connect(self.set_buttons_enabled)
        b.results.connect(self.refresh_list)
        b.busy.connect(self.set_busy)

    # -------------------------------------------------------------- 关闭
    def closeEvent(self, event):
        app = self.app
        if app.busy:
            if not _show_confirm(
                    self, "确认退出",
                    "任务正在执行，退出将请求中止当前操作。\n确定要退出吗？"):
                event.ignore()
                return
            app.request_cancel()
        t = app._worker_thread
        if t is not None and t.is_alive():
            # 带超时 join，不无限等待
            t.join(timeout=5.0)
            if t.is_alive():
                # 线程仍未结束：屏蔽信号桥，避免其在窗口销毁后继续触碰 Qt 对象
                app._bus.blockSignals(True)
        # 兜底清理尚未删除的任务临时文件（正常路径由线程自行清理）
        app._cleanup_job(*(app._job_files or ()))
        event.accept()

    # -------------------------------------------------------------- 拖放
    def dragEnterEvent(self, e: QDragEnterEvent):
        # 仅在接受到本地文件 URL 时 accept；http 等远程链接不给"可放下"暗示
        if any(u.isLocalFile() for u in e.mimeData().urls()):
            e.acceptProposedAction()
            self.list.setProperty("dragOver", True)
            self.list.style().unpolish(self.list)
            self.list.style().polish(self.list)

    def dragLeaveEvent(self, e):
        self.list.setProperty("dragOver", False)
        self.list.style().unpolish(self.list)
        self.list.style().polish(self.list)

    def dropEvent(self, e: QDropEvent):
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        self.list.setProperty("dragOver", False)
        self.list.style().unpolish(self.list)
        self.list.style().polish(self.list)
        if paths:
            e.acceptProposedAction()
            self.app._on_drop_paths(paths)

    # -------------------------------------------------------------- 槽
    def append_log(self, msg, level):
        color_map = {
            "err": F["err"], "warn": F["warn"], "ok": F["ok"],
            "step": F["accent"], "dim": F["ink_tertiary"],
            "info": F["ink"],
        }
        sym_map = {
            "err": "\u2717", "warn": "\u26A0", "ok": "\u2713",
            "step": "\u25BB", "dim": "\u2022", "info": "\u2022",
        }
        color = color_map.get(level, F["ink"])
        sym = sym_map.get(level, "\u2022")
        esc = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self.log.appendHtml(
            f'<span style="color:{color};font-size:9pt">'
            f'<b>{sym}</b> {esc}</span>')
        sb = self.log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def set_progress(self, pct):
        self.progress.setValue(pct)
        # pct==0（任务启动重置）时清掉 format，避免新任务短暂显示上一轮的 100%
        self.progress.setFormat(f"  {pct}%" if pct > 0 else "")

    def set_status(self, text):
        self.status.setText(text)

    def set_buttons_enabled(self, enabled):
        for b in (self.btn_scan, self.btn_delete, *self._target_btns):
            b.setEnabled(enabled)

    def set_busy(self, busy):
        self.set_buttons_enabled(not busy)
        # 取消按钮与任务状态相反：仅 busy 时可用
        self.btn_cancel.setEnabled(bool(busy))

    def remove_current(self):
        self.app._remove_selected(self.list.currentRow())

    def refresh_list(self, results=None):
        # 记录当前选中路径，重建后重新选中
        cur = self.list.currentItem()
        cur_path = cur.data(Qt.ItemDataRole.UserRole + 1) if cur else None
        self.list.clear()
        for path in self.app.targets:
            typ = "\U0001F4C1 文件夹" if os.path.isdir(path) else "\U0001F4C4 文件"
            status = ""
            status_color = ""
            if results:
                rr = results.get(path)
                st = getattr(rr, "status", None) if rr else None
                smap = {
                    "deleted": ("\u2713 已删除", F["ok"]),
                    "reboot": ("\U0001F504 待重启", F["warn"]),
                    "failed": ("\u2717 失败", F["err"]),
                    "missing": ("\U0001F6AB 不存在", F["ink_tertiary"]),
                    "blocked": ("\U0001F6AB 已拦截", F["warn"]),
                }
                if st in smap:
                    status, status_color = smap[st]
            # 状态拼进显示文本：UserRole 没有任何 delegate/渲染读取，
            # 只存数据角色的话删除结果（✓已删除/✗失败/待重启/已拦截）在列表里不可见
            text = f"{path}  —  {status}" if status else f"{path}"
            item = QListWidgetItem(text)
            item.setToolTip(path)
            item.setData(Qt.ItemDataRole.UserRole + 1, path)
            if status:
                item.setData(Qt.ItemDataRole.UserRole, (status, status_color))
            self.list.addItem(item)
            if cur_path is not None and path.lower() == cur_path.lower():
                self.list.setCurrentItem(item)


# ===========================================================================
# 卡片容器组件（复用 PowerToys 风格的分组卡片）
# ===========================================================================
class _Card(QFrame):
    """Fluent 风格卡片：带标题、副标题和内容区的圆角白底容器。"""

    def __init__(self, title: str, subtitle: str = ""):
        super().__init__()
        self.setObjectName("fluentCard")
        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        # 卡片头部
        hdr = QWidget()
        hdr.setObjectName("cardHeader")
        hdl = QHBoxLayout(hdr)
        hdl.setContentsMargins(20, 14, 16, 0)
        ttl = QLabel(title)
        ttl.setObjectName("cardTitle")
        hdl.addWidget(ttl)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("cardSubtitle")
            hdl.addWidget(sub)
            hdl.addStretch(1)
        vl.addWidget(hdr)

        # 卡片内容区
        body = QWidget()
        body.setObjectName("cardBody")
        self.body_layout = QVBoxLayout(body)
        self.body_layout.setContentsMargins(20, 12, 16, 16)
        self.body_layout.setSpacing(12)
        vl.addWidget(body, 1)


# ===========================================================================
# 全局样式表（Windows 11 Fluent Design）
# ===========================================================================
def _fluent_qss():
    return f"""
    /* ========== 全局基础 ========== */
    QWidget {{
        font: 9pt "Segoe UI Variable", "Segoe UI", sans-serif;
        color: {F['ink']};
        background: transparent;
    }}

    /* ========== 主窗口背景 ========== */
    """ + f".{MainWindow.__name__} {{\n        background: {F['bg']};\n    }}\n" + f"""

    /* ========== 顶部标题栏 ========== */
    #header {{
        background: {F['card']};
        border-bottom: 1px solid {F['border']};
    }}
    #titleIcon {{
        font-size: 18px;
        color: {F['accent']};
        padding-right: 8px;
    }}
    #titleText {{
        font: bold 14pt "Segoe UI Variable", "Segoe UI";
        color: {F['ink']};
    }}

    /* ========== 主内容区 ========== */
    #mainContent {{
        background: {F['bg']};
    }}

    /* ========== 卡片 ========== */
    #fluentCard {{
        background: {F['card']};
        border: 1px solid {F['border']};
        border-radius: 8px;
    }}
    #cardHeader {{
        background: transparent;
        border: none;
    }}
    #cardTitle {{
        font: bold 12pt "Segoe UI Variable", "Segoe UI";
        color: {F['ink']};
        padding: 0;
    }}
    #cardSubtitle {{
        font: 9pt "Segoe UI Variable", "Segoe UI";
        color: {F['ink_secondary']};
        padding-left: 8px;
    }}
    #cardBody {{
        background: transparent;
        border: none;
        border-top: 1px solid {F['divider']};
    }}

    /* ========== 按钮 — 主要（蓝色填充）========== */
    #btnPrimary {{
        background: {F['accent']};
        color: #FFFFFF;
        border: none;
        border-radius: 4px;
        padding: 8px 20px;
        font: 9pt "Segoe UI Variable", "Segoe UI";
        font-weight: bold;
        min-width: 100px;
        min-height: 34px;
    }}
    #btnPrimary:hover {{
        background: {F['accent_hover']};
    }}
    #btnPrimary:pressed {{
        background: {F['accent']};
    }}
    #btnPrimary:disabled {{
        background: {F['accent_light']};
        color: {F['ink_tertiary']};
    }}

    /* ========== 按钮 — 危险（红色填充）========== */
    #btnDanger {{
        background: {F['danger']};
        color: #FFFFFF;
        border: none;
        border-radius: 4px;
        padding: 8px 20px;
        font: 9pt "Segoe UI Variable", "Segoe UI";
        font-weight: bold;
        min-width: 100px;
        min-height: 34px;
    }}
    #btnDanger:hover {{
        background: {F['danger_hover']};
    }}
    #btnDanger:pressed {{
        background: {F['danger']};
    }}
    #btnDanger:disabled {{
        background: {F['danger_light']};
        color: {F['ink_tertiary']};
    }}

    /* ========== 按钮 — 次要（文字/边框）========== */
    #btnSecondary {{
        background: transparent;
        color: {F['accent']};
        border: 1px solid {F['border']};
        border-radius: 4px;
        padding: 6px 14px;
        font: 9pt "Segoe UI Variable", "Segoe UI";
        min-height: 30px;
    }}
    #btnSecondary:hover {{
        background: {F['accent_light']};
        border-color: {F['accent']};
    }}
    #btnSecondary:pressed {{
        background: {F['border']};
    }}
    #btnSecondary:disabled {{
        color: {F['ink_tertiary']};
        border-color: {F['border']};
    }}

    /* ========== 默认 QPushButton 兜底 ========== */
    QPushButton:not(#btnPrimary):not(#btnDanger):not(#btnSecondary) {{
        background: {F['card']};
        color: {F['ink']};
        border: 1px solid {F['border']};
        border-radius: 4px;
        padding: 6px 16px;
        font: 9pt "Segoe UI Variable", "Segoe UI";
        min-height: 30px;
    }}
    QPushButton:not(#btnPrimary):not(#btnDanger):not(#btnSecondary):hover {{
        background: {F['accent_light']};
        border-color: {F['accent']};
    }}

    /* ========== 复选框（自绘 _CheckButton，仅控制字体/间距）========== */
    #fluentCheckBox {{
        spacing: 10px;
        color: {F['ink']};
        font: 9pt "Segoe UI Variable", "Segoe UI";
    }}
    QCheckBox {{
        spacing: 10px;
        color: {F['ink']};
        font: 9pt "Segoe UI Variable", "Segoe UI";
    }}

    /* ========== 目标列表 ========== */
    #targetList {{
        background: {F['bg']};
        border: 1px solid {F['border']};
        border-radius: 4px;
        padding: 4px;
        outline: none;
        font: 9pt "Segoe UI Variable", "Segoe UI";
    }}
    #targetList[dragOver="true"] {{
        border: 2px dashed {F['accent']};
        background: {F['accent_light']};
    }}
    QListWidget::item {{
        padding: 8px 10px;
        border-radius: 4px;
        color: {F['ink']};
        border-bottom: 1px solid {F['divider']};
    }}
    QListWidget::item:selected {{
        background: {F['accent_light']};
        color: {F['ink']};
    }}
    QListWidget::item:hover:!selected {{
        background: #F5F5F5;
    }}
    QListWidget::item:alternate {{
        background: #FAFAFA;
    }}

    /* ========== 日志区 ========== */
    #logArea {{
        background: {F['bg']};
        border: 1px solid {F['border']};
        border-radius: 4px;
        padding: 8px 10px;
        font: 8.5pt "Consolas", "Cascadia Mono", "Segoe UI Mono", monospace;
        color: {F['ink_secondary']};
    }}

    /* ========== 进度条（足够高以容纳百分比文字）========== */
    #fluentProgress {{
        background: {F['border']};
        border: none;
        border-radius: 4px;
        height: 22px;
        text-align: center;
        font: 8pt "Segoe UI Variable", "Segoe UI";
        color: {F['ink_secondary']};
        padding: 0 6px;
    }}
    #fluentProgress::chunk {{
        background: {F['accent']};
        border-radius: 4px;
    }}

    /* ========== 状态标签 ========== */
    #statusLabel {{
        font: 9pt "Segoe UI Variable", "Segoe UI";
        color: {F['ink_tertiary']};
        padding-top: 4px;
    }}

    /* ========== 滚动条 ========== */
    QScrollBar:vertical {{
        background: transparent;
        width: 12px;
        margin: 2px;
    }}
    QScrollBar::handle:vertical {{
        background: {F['scrollbar']};
        border-radius: 6px;
        min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: #B0B0B0;
    }}
    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {{
        height: 0;
        border: none;
        background: none;
    }}
    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical {{
        background: transparent;
    }}
    QScrollBar:horizontal {{
        background: transparent;
        height: 12px;
        margin: 2px;
    }}
    QScrollBar::handle:horizontal {{
        background: {F['scrollbar']};
        border-radius: 6px;
        min-width: 30px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: #B0B0B0;
    }}
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {{
        width: 0;
        border: none;
        background: none;
    }}
    QScrollBar::add-page:horizontal,
    QScrollBar::sub-page:horizontal {{
        background: transparent;
    }}

    /* ========== 对话框（Fluent 白色风格）========== */
    #fluentDialog {{
        background: {F['card']};
        border: 1px solid {F['border']};
        border-radius: 8px;
    }}
    #dialogBody {{
        background: {F['card']};
        border: none;
        border-radius: 8px;
    }}
    #dialogIcon {{
        font-size: 32px;
        color: {F['accent']};
        min-width: 40px;
        min-height: 40px;
        qproperty-alignment: AlignCenter;
    }}
    #dialogIconWarn {{
        font-size: 28px;
        color: #E6A23C;
        min-width: 36px;
        min-height: 36px;
        qproperty-alignment: AlignCenter;
    }}
    #dialogIconErr {{
        font-size: 28px;
        color: {F['err']};
        min-width: 36px;
        min-height: 36px;
        qproperty-alignment: AlignCenter;
    }}
    #dialogMessage {{
        font: 10pt "Segoe UI Variable", "Segoe UI";
        color: {F['ink']};
        line-height: 1.4;
    }}
    #dialogBtnYes {{
        background: {F['accent']};
        color: #FFFFFF;
        border: none;
        border-radius: 4px;
        font: 9pt "Segoe UI Variable", "Segoe UI";
        font-weight: bold;
        padding: 4px 16px;
    }}
    #dialogBtnYes:hover {{ background: {F['accent_hover']}; }}
    #dialogBtnYes:pressed {{ background: {F['accent']}; }}
    #dialogBtnNo {{
        background: transparent;
        color: {F['ink']};
        border: 1px solid {F['border']};
        border-radius: 4px;
        font: 9pt "Segoe UI Variable", "Segoe UI";
        padding: 4px 16px;
    }}
    #dialogBtnNo:hover {{
        background: {F['accent_light']};
        border-color: {F['accent']};
    }}
    #dialogBtnNo:pressed {{ background: {F['border']}; }}

    /* ========== 原生 QMessageBox 兜底 ========== */
    QMessageBox {{ background: {F['card']}; }}
    QMessageBox QLabel {{ color: {F['ink']}; background: {F['card']}; }}

    /* ========== 文件对话框（Qt 自绘，非原生）========== */
    QFileDialog {{ background: {F['card']}; }}
    QFileDialog QWidget {{ color: {F['ink']}; }}
    QFileDialog QLabel {{ color: {F['ink']}; background: transparent; }}
    QFileDialog QLineEdit {{
        background: {F['bg']};
        color: {F['ink']};
        border: 1px solid {F['border']};
        border-radius: 4px;
        padding: 4px 8px;
        font: 9pt "Segoe UI Variable", "Segoe UI";
    }}
    QFileDialog QLineEdit:focus {{ border-color: {F['accent']}; }}
    QFileDialog QTreeView {{
        background: {F['card']};
        color: {F['ink']};
        border: 1px solid {F['border']};
        border-radius: 4px;
        outline: 0;
    }}
    QFileDialog QTreeView::item {{ padding: 4px 6px; }}
    QFileDialog QTreeView::item:selected {{ background: {F['accent']}; color: #FFFFFF; }}
    QFileDialog QTreeView::item:hover {{ background: {F['accent_light']}; }}
    QFileDialog QComboBox {{
        background: {F['card']};
        color: {F['ink']};
        border: 1px solid {F['border']};
        border-radius: 4px;
        padding: 3px 8px;
    }}
    QFileDialog QComboBox QAbstractItemView {{
        background: {F['card']};
        color: {F['ink']};
        border: 1px solid {F['border']};
        selection-background-color: {F['accent_light']};
        selection-color: {F['ink']};
    }}
    QFileDialog QPushButton {{
        background: {F['accent']};
        color: #FFFFFF;
        border: none;
        border-radius: 4px;
        font: 9pt "Segoe UI Variable", "Segoe UI";
        padding: 5px 14px;
    }}
    QFileDialog QPushButton:hover {{ background: {F['accent_hover']}; }}
    QFileDialog QPushButton:pressed {{ background: {F['accent']}; }}
    QFileDialog QToolButton {{
        background: transparent;
        color: {F['ink']};
        border: none;
        padding: 4px;
    }}
    QFileDialog QToolButton:hover {{ background: {F['accent_light']}; }}
    QFileDialog QSidebar {{ background: {F['bg']}; }}
    """


# ---------------------------------------------------------------------------
def main():
    app = App()
    app.run()


if __name__ == "__main__":
    main()
