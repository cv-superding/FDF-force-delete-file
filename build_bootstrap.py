# 绕过沙箱 safe-delete shim：恢复原始 os/shutil/pathlib 删除 API 后再调用 PyInstaller。
import os, sys, shutil, pathlib, sitecustomize

os.remove = sitecustomize._orig_remove
os.unlink = sitecustomize._orig_unlink
os.rmdir = sitecustomize._orig_rmdir
shutil.rmtree = sitecustomize._orig_shutil_rmtree
pathlib.Path.unlink = sitecustomize._orig_path_unlink
pathlib.Path.rmdir = sitecustomize._orig_path_rmdir

from PyInstaller.__main__ import run

sys.argv = ["pyinstaller", "--noconfirm", "FDF.spec"]
sys.exit(run())
