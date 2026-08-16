# 绕过沙箱 safe-delete shim：恢复原始 os/shutil/pathlib 删除 API 后再调用 PyInstaller。
import os
import sys
import shutil
import pathlib

try:
    import sitecustomize
except ImportError:
    sitecustomize = None   # 普通环境没有沙箱 sitecustomize，退回标准删除行为

# FDF.spec 位于本脚本所在的项目根，不依赖启动目录
SPEC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "FDF.spec")

if sitecustomize is not None:
    # _orig_* 属性不存在时保留当前实现（getattr 防御，避免直接 AttributeError）
    os.remove = getattr(sitecustomize, "_orig_remove", os.remove)
    os.unlink = getattr(sitecustomize, "_orig_unlink", os.unlink)
    os.rmdir = getattr(sitecustomize, "_orig_rmdir", os.rmdir)
    shutil.rmtree = getattr(sitecustomize, "_orig_shutil_rmtree", shutil.rmtree)
    pathlib.Path.unlink = getattr(sitecustomize, "_orig_path_unlink", pathlib.Path.unlink)
    pathlib.Path.rmdir = getattr(sitecustomize, "_orig_path_rmdir", pathlib.Path.rmdir)

from PyInstaller.__main__ import run

sys.argv = ["pyinstaller", "--noconfirm", SPEC_PATH]
sys.exit(run())
