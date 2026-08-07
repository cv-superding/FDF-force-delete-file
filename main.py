"""FDF 强制删除工具 — 程序入口（供 PyInstaller 打包）。

两种运行模式：
    FDF.exe                        普通权限启动图形界面（拖放可用）
    FDF.exe --worker <job.json>    提权工作进程，由界面通过 UAC 拉起，执行实际删除
"""
import os
import sys
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))


def main():
    argv = sys.argv[1:]
    if len(argv) >= 2 and argv[0] == "--worker":
        from fdf.worker import run_worker
        sys.exit(run_worker(argv[1]))
    from fdf.gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        msg = "FDF 启动失败：\n\n" + traceback.format_exc()
        try:
            import tempfile
            with open(os.path.join(tempfile.gettempdir(), "fdf_error.log"),
                      "w", encoding="utf-8") as _f:
                _f.write(msg)
        except Exception:
            pass
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, msg, "FDF 强制删除工具", 0x10)
        except Exception:
            sys.stderr.write(msg)
