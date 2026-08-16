"""GUI 运行时冒烟测试：真正创建窗口并运行消息循环数秒，验证子控件创建与 ctypes 调用正确。"""
import os
import sys

try:
    from PySide6.QtCore import QTimer
except ImportError:
    print("SKIP: 本机未安装 PySide6，跳过 GUI 冒烟测试")
    sys.exit(0)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import fdf.gui as gui
from fdf.gui import App


class _SmokeWindow(gui.MainWindow):
    """冒烟窗口：首次显示时跑一次基础逻辑，并安排定时器自动退出消息循环。"""

    def showEvent(self, event):
        super().showEvent(event)
        if getattr(self, "_smoke_armed", False):
            return
        self._smoke_armed = True
        # 此时已处于主线程、QApplication 与全部控件已创建
        self.app._add_target(os.path.abspath(__file__))
        self.app._log("冒烟测试：控件创建成功", "ok")
        qapp = gui.QApplication.instance()
        QTimer.singleShot(2500, qapp.quit)   # 常规退出
        QTimer.singleShot(6000, qapp.quit)   # 超时兜底


def main():
    original_cls = gui.MainWindow
    gui.MainWindow = _SmokeWindow
    app = App()
    try:
        try:
            app.run()   # 正常以 sys.exit(exec()) 结束
        except SystemExit:
            pass
        print("SMOKE_OK: 窗口创建并运行消息循环成功，已自动退出")
    except Exception:  # noqa
        import traceback
        print("SMOKE_FAIL:")
        traceback.print_exc()
        raise SystemExit(1)
    finally:
        gui.MainWindow = original_cls


if __name__ == "__main__":
    main()
