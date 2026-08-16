"""
worker.py — 提权工作进程。

为什么需要它：
    Windows 的 UIPI（用户界面特权隔离）禁止普通权限的资源管理器向
    「以管理员运行」的窗口拖放文件，光标只会显示禁止图标，这是系统设计，
    无法通过 IDropTarget / ChangeWindowMessageFilter 绕过。

    因此 FDF 采用双进程模型：
        · 主界面以普通权限（asInvoker）运行 —— 与资源管理器同级，拖放正常；
        · 真正执行删除时，用 ShellExecute "runas" 拉起同一个 exe 的 worker 模式，
          由这个提权子进程完成删除，并把日志/进度以 JSONL 流写回文件，
          主界面轮询该文件实时回显。

任务文件（JSON）：
    {"kind": "delete"|"scan", "targets": [...], "options": {...}, "out": "...jsonl"}

输出事件（JSONL，每行一个 JSON）：
    {"t":"log","m":"...","l":"info"}
    {"t":"prog","d":3,"n":10}
    {"t":"proc","name":"x.exe","pid":123,"count":2}
    {"t":"res","path":"...","status":"deleted",...}
    {"t":"end","ok":true}
"""

import json
import os
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fdf.engine import ForceDeleter, Options   # noqa: E402


class _Emitter:
    """把事件按行写入输出文件，每行立即 flush，供主界面尾随读取。"""

    def __init__(self, path):
        self._fp = open(path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def emit(self, **ev):
        line = json.dumps(ev, ensure_ascii=False)
        with self._lock:
            self._fp.write(line + "\n")
            self._fp.flush()
            try:
                os.fsync(self._fp.fileno())
            except Exception:  # noqa
                pass

    def close(self):
        try:
            self._fp.close()
        except Exception:  # noqa
            pass


def run_worker(job_path):
    """执行任务文件描述的工作，返回进程退出码。"""
    # 任务文件读取/解析失败时无输出文件可写（out 路径就在 job 里），
    # 只能写 stderr 并以非零退出码结束；主界面按"进程退出且无新数据"分支兜底。
    try:
        with open(job_path, "r", encoding="utf-8") as f:
            job = json.load(f)
    except Exception as e:  # noqa
        sys.stderr.write(f"FDF worker: 任务文件读取失败: {e}\n")
        return 2

    em = None
    ok = True
    try:
        out_path = job["out"]
        cancel_path = job.get("cancel") or (job_path + ".cancel")
        em = _Emitter(out_path)
        cancel = threading.Event()

        # 主界面通过创建 .cancel 文件来请求中止
        def watch_cancel():
            while not cancel.is_set():
                if os.path.exists(cancel_path):
                    cancel.set()
                    return
                time.sleep(0.3)

        threading.Thread(target=watch_cancel, daemon=True).start()

        o = job.get("options") or {}
        opt = Options(
            unlock_handles=bool(o.get("unlock_handles", True)),
            kill_processes=bool(o.get("kill_processes", False)),
            take_ownership=bool(o.get("take_ownership", True)),
            schedule_reboot=bool(o.get("schedule_reboot", True)),
            shred=bool(o.get("shred", False)),
        )
        d = ForceDeleter(
            opt,
            log=lambda m, l="info": em.emit(t="log", m=str(m), l=l),
            progress=lambda done, total, s="": em.emit(t="prog", d=done, n=total),
            cancel=cancel,
        )
        targets = job.get("targets") or []
        if job.get("kind") == "scan":
            procs = d.scan(targets)
            for p in procs:
                em.emit(t="proc", name=p.get("name", ""), pid=p.get("pid", 0),
                        count=p.get("count", 0))
        else:
            for r in d.delete(targets):
                em.emit(t="res", path=r.path, status=r.status, detail=r.detail,
                        files=r.files, folders=r.folders, bytes=r.bytes)
    except Exception:  # noqa
        ok = False
        if em is not None:
            em.emit(t="log", m="工作进程出错：\n" + traceback.format_exc(), l="err")
        else:
            sys.stderr.write(traceback.format_exc())
    finally:
        if em is not None:
            em.emit(t="end", ok=ok)
            em.close()
    return 0 if ok else 1
