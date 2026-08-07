"""循环稳定性测试：反复 清理残留 -> 重建样本 -> 独占锁定 -> 强制删除 -> 验证，共 N 轮。"""
import os
import subprocess
import sys
import time

ROOT = os.path.join(os.environ.get("TEMP", "."), "fdf_testbed")
HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

sys.path.insert(0, os.path.join(HERE, "..", "src"))
from fdf.engine import ForceDeleter, Options


def build():
    subprocess.run([PY, os.path.join(HERE, "make_stubborn.py")], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_locker():
    p = subprocess.Popen([PY, os.path.join(HERE, "make_stubborn.py"), "lock",
                          os.path.join(ROOT, "locked.bin")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p


def cleanup():
    """用引擎自身清理上一轮残留（最稳，能处理权限/锁定）。"""
    d = ForceDeleter(Options(unlock_handles=True, kill_processes=False,
                            take_ownership=True, schedule_reboot=False),
                    log=lambda m, l="i": None)
    try:
        d.delete([ROOT])
    except Exception:
        pass


def main(rounds=6):
    for i in range(1, rounds + 1):
        t0 = time.time()
        cleanup()
        build()
        locker = start_locker()
        time.sleep(1.2)

        def log(m, l="info"):
            pass

        opt = Options(unlock_handles=True, kill_processes=False,
                      take_ownership=True, schedule_reboot=False)
        d = ForceDeleter(opt, log=log)
        try:
            results = d.delete([ROOT])
        finally:
            if locker.poll() is None:
                locker.terminate()
                try:
                    locker.wait(timeout=3)
                except Exception:
                    locker.kill()

        status = results[0].status
        elapsed = time.time() - t0
        ok = not os.path.exists(ROOT)
        mark = "OK " if (ok and status == "deleted") else "!!!"
        print(f"[{mark}] 轮次 {i:>2} | 状态={status:<7} | 删除成功={ok} | 耗时 {elapsed:.1f}s",
              flush=True)
        if not ok:
            print("     !! 目录仍存在，下轮将重试清理", flush=True)
        sys.stdout.flush()
    print("全部轮次完成", flush=True)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 6)
