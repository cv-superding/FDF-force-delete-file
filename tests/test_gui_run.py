"""GUI 运行时冒烟测试：真正创建窗口并运行消息循环数秒，验证子控件创建与 ctypes 调用正确。"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from fdf.gui import App, ID_DELETE


def main():
    app = App()
    # 给 run() 一个自动退出的钩子：窗口创建后 2.5 秒自动结束
    orig_create = app._create_controls

    def patched_create():
        orig_create()
        # 模拟添加目标并刷新列表，验证运行时逻辑
        app._add_target(os.path.abspath(__file__))
        app._log("冒烟测试：控件创建成功", "ok")
        # 2.5 秒后退出消息循环
        import threading
        def quit_later():
            time.sleep(2.5)
            import ctypes
            user32 = ctypes.WinDLL("user32")
            user32.PostQuitMessage(0)
        threading.Thread(target=quit_later, daemon=True).start()

    app._create_controls = patched_create
    try:
        app.run()
        print("SMOKE_OK: 窗口创建并运行消息循环成功，已自动退出")
    except Exception as e:  # noqa
        import traceback
        print("SMOKE_FAIL:", repr(e))
        traceback.print_exc()


if __name__ == "__main__":
    main()
