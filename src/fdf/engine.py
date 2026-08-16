"""
engine.py — 强制删除引擎

删除策略是一条"由轻到重"的递进链，只有前一级失败才升级到下一级，
尽量减少对系统的副作用：

    L0  清除只读/隐藏/系统属性
    L1  POSIX 语义删除 (FileDispositionInfoEx)  —— 可删掉仍被打开的文件
    L2  常规删除 DeleteFileW / RemoveDirectoryW
    L3  夺取所有权 + 重写 DACL，再回到 L1/L2      —— 解决"拒绝访问"
    L4  强制关闭其他进程持有的文件句柄，再重试     —— 解决"文件被占用"
    L5  结束占用进程（Restart Manager 定位），再重试
    L6  登记为重启时删除 (MoveFileEx)              —— 最后兜底
"""

import os
import sys
import threading
import time
from dataclasses import dataclass, field

from . import winapi as w


def _build_protected():
    """
    动态构造受保护路径集合，不硬编码 C: 盘（系统可能装在其他盘符）。

    _PROTECTED_EXACT : 整体删除被禁止的路径（用户仍可删其子目录，如卸载残留）
    _PROTECTED_TREE  : 整棵子树都受保护（Windows 目录内任何东西都不允许动）
    """
    sysdrive = (os.environ.get("SystemDrive") or "C:").rstrip(":\\").lower()  # "c"
    exact = {f"{sysdrive}:\\users", f"{sysdrive}:\\programdata",
             f"{sysdrive}:\\program files", f"{sysdrive}:\\program files (x86)",
             f"{sysdrive}:\\perflogs"}
    tree = {f"{sysdrive}:\\boot", f"{sysdrive}:\\efi", f"{sysdrive}:\\recovery",
            f"{sysdrive}:\\system volume information",
            f"{sysdrive}:\\config.msi"}
    for c in "abcdefghijklmnopqrstuvwxyz":
        exact.add(f"{c}:\\")                    # 所有卷根
        exact.add(f"{c}:\\$recycle.bin")        # 所有盘的回收站
        tree.add(f"{c}:\\windows")              # 任何盘符下的 Windows 目录（覆盖第二系统盘）
        tree.add(f"{c}:\\system volume information")
    return exact, tree


_PROTECTED_EXACT, _PROTECTED_TREE = _build_protected()

STATUS_DELETED = "deleted"
STATUS_REBOOT = "reboot"
STATUS_FAILED = "failed"
STATUS_MISSING = "missing"
STATUS_BLOCKED = "blocked"


@dataclass
class Options:
    unlock_handles: bool = True     # 强制关闭占用句柄
    kill_processes: bool = False    # 结束占用进程
    take_ownership: bool = True     # 接管所有权与权限
    schedule_reboot: bool = True    # 兜底：重启时删除
    shred: bool = False             # 删除前覆写内容


@dataclass
class ItemResult:
    path: str
    status: str = STATUS_FAILED
    detail: str = ""
    files: int = 0
    folders: int = 0
    bytes: int = 0
    failed_leaves: list = field(default_factory=list)


def is_protected(path: str) -> bool:
    """
    判断是否为受保护的系统关键路径。

    防绕过：先用 w.norm_path 做权威规范化（剥 \\\\?\\ 前缀、展开 8.3 短名、
    去尾分隔符），再用 w.real_path 跟随符号链接/junction 解析出物理路径一并校验，
    保证"护栏比较的路径"与"实际删除的路径"是同一个对象。
    """
    candidates = [w.norm_path(path).lower()]
    rp = w.real_path(path)
    if rp:
        candidates.append(w.norm_path(rp).lower())

    for p in candidates:
        if len(p) <= 3 and p.rstrip("\\").endswith(":"):
            return True  # 卷根（X: 或 X:\\）
        if p.startswith("\\\\") and p.count("\\") <= 3:
            return True  # UNC 共享根 \\\\server\\share
        if p in _PROTECTED_EXACT:
            return True
        for q in _PROTECTED_TREE:
            if p == q or p.startswith(q + "\\"):
                return True

    # 用户主目录本身
    up = os.environ.get("USERPROFILE", "")
    if up:
        upn = w.norm_path(up).lower()
        if any(p == upn for p in candidates):
            return True
    # 正在运行的本程序所在目录
    try:
        self_dir = os.path.dirname(os.path.abspath(sys.executable)).lower()
        if any(p == w.norm_path(self_dir).lower() for p in candidates):
            return True
    except Exception:
        pass
    return False


def format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


class ForceDeleter:
    """强制删除执行器。log(msg, level) 用于回显，progress(done, total, text) 用于进度。"""

    def __init__(self, options: Options, log=None, progress=None, cancel: threading.Event = None):
        self.opt = options
        self._log = log or (lambda m, l="info": None)
        self._progress = progress or (lambda d, t, s="": None)
        self.cancel = cancel or threading.Event()
        self.last_error: dict[str, int] = {}
        self._stats = {"files": 0, "folders": 0, "bytes": 0}

    # ------------------------------------------------------------ 对外入口
    def delete(self, paths: list[str]) -> list[ItemResult]:
        enabled = w.enable_privileges()
        if enabled:
            self._log(f"已启用特权: {', '.join(n.replace('Privilege', '') for n in enabled)}", "dim")
        if not w.is_admin():
            self._log("当前非管理员身份运行，部分受保护文件可能无法删除", "warn")

        # 入口统一规范化（剥前缀/展开短名/去尾分隔符），护栏与删除操作共用同一写法
        paths = [w.norm_path(p) for p in paths]

        results: dict[str, ItemResult] = {}
        pending: list[str] = []

        for p in paths:
            r = ItemResult(path=p)
            results[p] = r
            if not w.path_exists(p):
                r.status, r.detail = STATUS_MISSING, "路径不存在"
                continue
            if is_protected(p):
                r.status, r.detail = STATUS_BLOCKED, "系统关键路径，已拒绝执行"
                self._log(f"[拦截] {p} 是系统关键路径，跳过", "err")
                continue
            pending.append(p)

        if not pending:
            return list(results.values())

        # ---------- 第 1 轮：属性清理 + POSIX 删除 + 常规删除 ----------
        self._log("步骤 1/5 · 常规与 POSIX 语义删除", "step")
        pending = self._sweep(pending, results)

        # ---------- 第 2 轮：接管所有权与权限 ----------
        if pending and self.opt.take_ownership and not self.cancel.is_set():
            self._log("步骤 2/5 · 接管所有权并重写权限", "step")
            leaves = self._collect_leaves(pending, results)
            done = 0
            for i, leaf in enumerate(leaves):
                if self.cancel.is_set():
                    break
                self._progress(i, len(leaves), "接管权限")
                if w.take_ownership(leaf, w.is_directory(leaf)):
                    done += 1
            if done == len(leaves):
                self._log(f"已对 {done} 个对象重设所有权与 DACL", "dim")
            else:
                self._log(f"所有权/DACL 重设成功 {done}/{len(leaves)}，部分对象保留原权限", "warn")
            pending = self._sweep(pending, results)

        # ---------- 第 3 轮：强制关闭占用句柄 ----------
        if pending and self.opt.unlock_handles and not self.cancel.is_set():
            self._log("步骤 3/5 · 扫描内核句柄表并强制解除占用", "step")
            leaves = self._collect_leaves(pending, results)
            if leaves:
                closed, procs = w.force_close_handles(
                    leaves, progress=lambda d, t: self._progress(d, t, "扫描句柄"))
                if closed:
                    self._log(f"已强制关闭 {closed} 个句柄，涉及：{', '.join(procs)}", "ok")
                else:
                    self._log("未找到可关闭的句柄", "dim")
                pending = self._sweep(pending, results)

        # ---------- 第 4 轮：结束占用进程 ----------
        if pending and self.opt.kill_processes and not self.cancel.is_set():
            self._log("步骤 4/5 · 结束占用进程", "step")
            leaves = self._collect_leaves(pending, results)
            killed = self._kill_lockers(leaves)
            if killed:
                self._log(f"已结束进程：{', '.join(killed)}", "ok")
                time.sleep(0.3)
                pending = self._sweep(pending, results)
            else:
                self._log("未定位到可结束的占用进程", "dim")

        # ---------- 第 5 轮：重启时删除 ----------
        if pending and self.opt.schedule_reboot and not self.cancel.is_set():
            self._log("步骤 5/5 · 登记为重启后删除", "step")
            for p in pending:
                r = results[p]
                leaves = r.failed_leaves or [p]
                ok_any = False
                skipped_dirs = 0
                for leaf in leaves:
                    # PFRO 不递归：非空目录登记了也删不掉，直接跳过并如实计数
                    if w.is_directory(leaf) and not w.is_reparse_point(leaf):
                        try:
                            next(iter(w.enum_dir(leaf)))
                            skipped_dirs += 1
                            continue
                        except StopIteration:
                            pass
                        except Exception:
                            pass
                    if w.schedule_delete_on_reboot(leaf):
                        ok_any = True
                if ok_any:
                    r.status = STATUS_REBOOT
                    extra = f"（{skipped_dirs} 个非空目录无法登记）" if skipped_dirs else ""
                    r.detail = "已登记，重启电脑后自动删除" + extra
                    self._log(f"[待重启] {p}{extra}", "warn")
                else:
                    r.detail = self._describe(p, r)
            pending = [p for p in pending if results[p].status != STATUS_REBOOT]

        for p in pending:
            r = results[p]
            r.status = STATUS_FAILED
            if not r.detail:
                r.detail = self._describe(p, r)

        return [results[p] for p in paths]

    # ------------------------------------------------------------ 占用扫描
    def scan(self, paths: list[str], sample_limit: int = 400) -> list[dict]:
        """扫描这些目标当前被哪些进程占用（只读，不做任何修改）。"""
        w.enable_privileges()
        targets: list[str] = []
        for p in paths:
            if not w.path_exists(p):
                continue
            if w.is_directory(p) and not w.is_reparse_point(p):
                for f in self._iter_files(p, sample_limit - len(targets)):
                    targets.append(f)
            else:
                targets.append(p)
            if len(targets) >= sample_limit:
                break

        found: dict[int, dict] = {}
        # 1) 内核直接问：谁打开了这个文件
        for i, t in enumerate(targets):
            if self.cancel.is_set():
                break
            self._progress(i, len(targets), "查询占用")
            pids, qerr = w.get_pids_using_file(t)
            if qerr not in (0, w.ERROR_FILE_NOT_FOUND, w.ERROR_PATH_NOT_FOUND):
                # 独占打开/权限不足等：检测不可用，与"无人占用"区分开
                self._log(f"占用查询不可用（{w.error_text(qerr)}）：{t}", "dim")
            for pid in pids:
                if pid in (0, 4):
                    continue
                item = found.setdefault(pid, {"pid": pid, "name": "", "image": "",
                                              "paths": set(), "source": "内核句柄"})
                item["paths"].add(t)

        # 2) Restart Manager 补充应用/服务级信息
        for chunk in (targets[i:i + 64] for i in range(0, len(targets), 64)):
            if self.cancel.is_set():
                break
            for proc in w.restart_manager_processes(chunk):
                pid = proc["pid"]
                if pid in (0, 4):
                    continue
                item = found.setdefault(pid, {"pid": pid, "name": "", "image": "",
                                              "paths": set(), "source": "Restart Manager"})
                item["name"] = item["name"] or proc["name"]
                item["image"] = item["image"] or proc["image"]

        out = []
        for pid, item in sorted(found.items()):
            image = item["image"] or w.get_process_image(pid)
            out.append({
                "pid": pid,
                "name": item["name"] or (os.path.basename(image) if image else f"PID {pid}"),
                "image": image,
                "count": len(item["paths"]),
                "sample": sorted(item["paths"])[:3],
            })
        return out

    # ------------------------------------------------------------ 内部实现
    def _sweep(self, pending: list[str], results: dict) -> list[str]:
        """对所有仍未删掉的根目标做一轮删除尝试，返回仍失败的根目标。"""
        still: list[str] = []
        for p in pending:
            if self.cancel.is_set():
                still.append(p)
                continue
            r = results[p]
            failures: list[str] = []
            self._stats = {"files": 0, "folders": 0, "bytes": 0}
            self._delete_tree(p, failures)
            r.files += self._stats["files"]
            r.folders += self._stats["folders"]
            r.bytes += self._stats["bytes"]
            if failures:
                r.failed_leaves = failures
                still.append(p)
            else:
                r.status = STATUS_DELETED
                r.detail = f"已删除 {r.files} 个文件 / {r.folders} 个文件夹，共 {format_size(r.bytes)}"
                r.failed_leaves = []
                self._log(f"[成功] {p} — {r.detail}", "ok")
        return still

    def _delete_tree(self, path: str, failures: list[str]) -> bool:
        """
        显式栈的迭代后序遍历删除。
        不用递归：长路径允许上万层嵌套，Python 递归到几千层就会打穿
        线程的 1MB C 栈直接 access violation（不是 RecursionError），
        worker 崩掉后主界面收不到 end 事件。
        """
        if self.cancel.is_set():
            return False
        ENTERED = 1  # 目录已入栈、子项已排入，等子项处理完后自身出栈删除
        stack: list[tuple[str, int]] = [(path, 0)]
        ok = True
        while stack:
            cur, state = stack.pop()
            if self.cancel.is_set():
                return False
            attrs = w.get_attributes(cur)
            if attrs == w.INVALID_FILE_ATTRIBUTES:
                continue  # 已不存在
            is_dir = bool(attrs & w.FILE_ATTRIBUTE_DIRECTORY)
            is_rp = bool(attrs & w.FILE_ATTRIBUTE_REPARSE_POINT)
            if state != ENTERED and is_dir and not is_rp:
                stack.append((cur, ENTERED))
                for name, _d, _rp, _sz in w.enum_dir(cur):
                    stack.append((os.path.join(cur, name), 0))
                continue
            size = 0 if is_dir else self._file_size(cur)
            if self._delete_leaf(cur, is_dir, attrs):
                if is_dir:
                    self._stats["folders"] += 1
                else:
                    self._stats["files"] += 1
                    self._stats["bytes"] += size
            else:
                failures.append(cur)
                ok = False
        return ok

    def _delete_leaf(self, path: str, is_dir: bool, attrs: int) -> bool:
        if attrs & (w.FILE_ATTRIBUTE_READONLY | w.FILE_ATTRIBUTE_HIDDEN | w.FILE_ATTRIBUTE_SYSTEM):
            w.clear_attributes(path)

        if self.opt.shred and not is_dir:
            # 覆写失败（权限/共享冲突/符号链接）时如实告知，内容可能仍可恢复
            try:
                shredded = w.overwrite_file(path)
            except Exception:  # noqa
                shredded = False
            if not shredded:
                self._log(f"警告：覆写失败，内容可能仍可恢复 — {path}", "warn")

        err = 0
        for i in range(3):
            ok, e1 = w.posix_delete(path, is_dir)
            if ok:
                return True
            ok, e2 = w.plain_delete(path, is_dir)
            if ok:
                return True
            err = e2 or e1
            if err in (w.ERROR_FILE_NOT_FOUND, w.ERROR_PATH_NOT_FOUND):
                return True
            # 只对"瞬时占用"类错误重试；ACCESS_DENIED 重试无意义（本轮内
            # 不会有状态变化），DIR_NOT_EMPTY 意味着有子项本轮没删掉，直接升级
            if err not in (w.ERROR_SHARING_VIOLATION, w.ERROR_LOCK_VIOLATION):
                break
            time.sleep(0.01 * (i + 1))

        self.last_error[path] = err
        return False

    def _collect_leaves(self, pending: list[str], results: dict) -> list[str]:
        leaves: list[str] = []
        seen = set()
        for p in pending:
            for leaf in (results[p].failed_leaves or [p]):
                k = leaf.lower()
                if k not in seen:
                    seen.add(k)
                    leaves.append(leaf)
        return leaves

    def _kill_lockers(self, leaves: list[str]) -> list[str]:
        pids: dict[int, str] = {}
        for leaf in leaves[:400]:
            pids_using, _err = w.get_pids_using_file(leaf)
            for pid in pids_using:
                if pid not in (0, 4):
                    pids.setdefault(pid, "")
        for chunk in (leaves[i:i + 64] for i in range(0, min(len(leaves), 400), 64)):
            for proc in w.restart_manager_processes(chunk):
                if proc["pid"] not in (0, 4):
                    pids[proc["pid"]] = proc["name"]

        mypid = w.GetCurrentProcessId()
        killed = []
        for pid, name in pids.items():
            if pid == mypid:
                continue
            image = w.get_process_image(pid)
            base = os.path.basename(image).lower() if image else ""
            # 关键系统进程一律不动（与 winapi.CRITICAL_PROCESSES 同一份名单）
            if base in w.CRITICAL_PROCESSES:
                self._log(f"跳过系统关键进程 {base} (PID {pid})", "warn")
                continue
            if w.kill_process(pid):
                killed.append(f"{name or base or 'PID'} (PID {pid})")
        return killed

    def _iter_files(self, root: str, limit: int):
        if limit <= 0:
            return
        count = 0
        stack = [root]
        while stack and count < limit:
            cur = stack.pop()
            try:
                for name, is_dir, is_rp, _ in w.enum_dir(cur):
                    full = os.path.join(cur, name)
                    if is_dir and not is_rp:
                        stack.append(full)
                    else:
                        yield full
                        count += 1
                        if count >= limit:
                            return
            except Exception:
                continue

    @staticmethod
    def _file_size(path: str) -> int:
        try:
            return os.path.getsize(w.long_path(path))
        except Exception:
            return 0

    def _describe(self, root: str, r: ItemResult) -> str:
        leaves = r.failed_leaves or [root]
        err = self.last_error.get(leaves[0], 0)
        txt = w.error_text(err) if err else "无法删除"
        return f"{txt}（仍有 {len(leaves)} 个对象未删除）"
