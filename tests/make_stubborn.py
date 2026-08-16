"""生成各种"顽固文件"测试样本，并可选地以独占方式锁住其中一个文件。"""
import ctypes
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from fdf import winapi as w  # noqa: E402

ROOT = os.path.join(os.environ.get("TEMP", "."), "fdf_testbed")


def build():
    os.makedirs(ROOT, exist_ok=True)

    # 1. 普通文件
    with open(os.path.join(ROOT, "normal.txt"), "w", encoding="utf-8") as f:
        f.write("hello" * 100)

    # 2. 只读 + 隐藏 + 系统
    p = os.path.join(ROOT, "readonly_hidden.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("stubborn")
    w.SetFileAttributesW(p, w.FILE_ATTRIBUTE_READONLY | w.FILE_ATTRIBUTE_HIDDEN
                         | w.FILE_ATTRIBUTE_SYSTEM)

    # 3. 嵌套目录 + 超长路径
    deep = ROOT
    for i in range(14):
        deep = os.path.join(deep, "very_long_directory_segment_%02d_xxxxxxxxxxxxxxxxxxxx" % i)
    os.makedirs(w.long_path(deep), exist_ok=True)
    with open(w.long_path(os.path.join(deep, "deep.txt")), "w") as f:
        f.write("deep file beyond MAX_PATH")

    # 4. 非法/保留名（Windows 资源管理器无法删除）
    bad = w.long_path(os.path.join(ROOT, "trailing.space. "))
    h = w.CreateFileW(bad, w.GENERIC_WRITE, 0, None, 2, 0, None)
    if h != w.INVALID_HANDLE_VALUE:
        w.CloseHandle(h)

    # 5. 拒绝访问：清空 DACL
    p = os.path.join(ROOT, "no_access.txt")
    with open(p, "w") as f:
        f.write("denied")
    acl = ctypes.create_string_buffer(1024)
    w.InitializeAcl(acl, 1024, w.ACL_REVISION)  # 空 ACL = 谁都没权限
    namebuf = ctypes.create_unicode_buffer(p)
    rc = w.SetNamedSecurityInfoW(namebuf, w.SE_FILE_OBJECT,
                                 w.DACL_SECURITY_INFORMATION | w.PROTECTED_DACL_SECURITY_INFORMATION,
                                 None, None, ctypes.cast(acl, w.LPVOID), None)
    print("  set empty DACL rc =", rc)

    # 6. 被独占占用的文件
    p = os.path.join(ROOT, "locked.bin")
    with open(p, "wb") as f:
        f.write(os.urandom(4096))

    print("测试样本已生成:", ROOT)
    return ROOT


def lock_forever(path):
    """以 share=0 独占打开文件并常驻，模拟"文件被占用"。"""
    h = w.CreateFileW(w.long_path(path), w.GENERIC_WRITE, 0, None, 3, 0, None)
    if h == w.INVALID_HANDLE_VALUE:
        print("LOCK_FAILED", ctypes.get_last_error())
        return
    print("LOCKED", os.getpid(), flush=True)
    while True:
        time.sleep(1)


def cleanup():
    """删除 %TEMP%\\fdf_testbed 整个目录，给测试残留提供清理入口。"""
    shutil.rmtree(ROOT, ignore_errors=True)
    print("测试目录已清理:", ROOT)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "lock":
        lock_forever(sys.argv[2])
    elif "--cleanup" in sys.argv[1:]:
        cleanup()
    else:
        build()
