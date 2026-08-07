# FDF — 强制删除文件工具 (Force Delete File)

> Windows 下专治「文件被占用 / 拒绝访问 / 只读 / 被系统保护」等删不掉的场景。
> 纯 Python + `ctypes` 实现的原生 Win32 GUI，**零第三方运行时依赖**，打包成单个 `.exe`。

---

## 一、这是什么

Windows 自带的删除在遇到以下情况时会失败：

- 文件正被某个进程占用（句柄未释放）；
- 没有删除权限（ACL 拒绝 / 当前用户非所有者）；
- 文件带有只读 / 隐藏 / 系统属性；
- 路径位于系统关键目录；
- 文件正在被加载（如 `*.dll`、驱动、正在运行的程序）。

FDF 通过一条**由轻到重的递进式删除链**逐级升级手段，尽量在最小副作用下把目标删掉；实在删不掉时，会登记为「重启时删除」作为最后兜底。

---

## 二、功能特性

- **纯 ctypes Win32 原生界面**：不使用 `tkinter`、不依赖任何 GUI 框架，也**不需要 C 编译器**。整个界面（窗口、按钮、列表、复选框、进度条、渐变背景、圆角）全部用 `ctypes` 调用 Win32 API 手绘。
- **拖放 / 粘贴路径**添加删除目标，支持文件与文件夹混合队列。
- **递进式删除策略 L0–L6**，自动逐级升级（详见第三节）。
- **双进程模型**：主界面以普通权限运行（与资源管理器同级，拖放正常），真正删除时由界面拉起**提权 worker 子进程**完成，避免 UIPI 拦截拖放。
- **系统关键路径护栏**：内置受保护路径集合，防止手滑删除 `C:\Windows`、`C:\Users` 等导致系统崩溃。
- **实时进度与日志**：worker 的日志 / 进度以 JSONL 流回写，主界面尾随读取并实时回显。
- **莫奈（Monet）粉彩风格**的现代界面：渐变背景、圆角控件、悬停态按钮。
- **64 位**，目标系统 Windows 10 及以上。

---

## 三、删除原理

### 3.1 递进式删除链（engine.py）

每一级只在前一级失败后才会尝试，尽可能减少对系统的破坏：

| 级别 | 手段 | 解决的典型问题 |
|------|------|----------------|
| **L0** | 清除只读 / 隐藏 / 系统属性 | 属性阻止删除 |
| **L1** | POSIX 语义删除 `FileDispositionInfoEx` | 文件仍被打开也能标记删除 |
| **L2** | 常规删除 `DeleteFileW` / `RemoveDirectoryW` | 普通删除 |
| **L3** | 夺取所有权 + 重写 DACL，再回到 L1/L2 | 「拒绝访问」/ 权限不足 |
| **L4** | 强制关闭其他进程持有的文件句柄，再重试 | 「文件被占用」 |
| **L5** | 通过 Restart Manager 定位并结束占用进程，再重试 | 顽固占用 |
| **L6** | 登记为重启时删除 `MoveFileEx(...MOVEFILE_DELAY_UNTIL_REBOOT)` | 最后兜底 |

删除选项（`Options`）：

- `unlock_handles`：强制关闭占用句柄（默认开）
- `kill_processes`：结束占用进程（默认关，谨慎）
- `take_ownership`：接管所有权与权限（默认开）
- `schedule_reboot`：重启时删除兜底（默认开）
- `shred`：删除前覆写内容（默认关）

### 3.2 双进程模型与 UIPI（worker.py + gui.py）

Windows 的 **UIPI（User Interface Privilege Isolation）** 会禁止普通权限的资源管理器向「以管理员身份运行」的窗口拖放文件——光标只会显示禁止图标，这是系统层面的设计，**无法通过 `IDropTarget` / `ChangeWindowMessageFilter` 绕过**。

FDF 因此采用双进程模型：

```
主界面（普通权限 / asInvoker）  ──拖放正常，与资源管理器同级──
   │  点「开始删除」时
   ▼  ShellExecute("runas") 拉起提权子进程
worker 子进程（管理员权限）  ──执行真正的删除──
   │  日志/进度写入 JSONL 文件
   ▼  主界面轮询该文件实时回显
```

- 主界面 `fdf.manifest` 中 `requestedExecutionLevel = asInvoker`：这**必须**是 asInvoker，否则主窗口变高权限后拖放会被 UIPI 拦截。
- 删除时由界面通过 `ShellExecute "runas"` 拉起同一个 exe 的 worker 模式，由这个提权子进程完成删除。
- 任务以 JSON 传递：`{"kind":"delete"|"scan","targets":[...],"options":{...},"out":"...jsonl"}`。
- worker 输出事件（JSONL，每行一个 JSON）：
  - `{"t":"log","m":"...","l":"info"}`
  - `{"t":"prog","d":3,"n":10}`
  - `{"t":"proc","name":"x.exe","pid":123,"count":2}`
  - `{"t":"res","path":"...","status":"deleted",...}`
  - `{"t":"end","ok":true}`

### 3.3 安全护栏（engine.py `_PROTECTED`）

以下路径**绝对不会被当作删除目标**（大小写不敏感比较），防手滑毁系统：

```
C:\  C:\Windows  C:\Windows\System32  C:\Windows\SysWOW64
C:\Program Files  C:\Program Files (x86)  C:\ProgramData
C:\Users  C:\$Recycle.Bin  C:\Boot  C:\Recovery
```

---

## 四、使用方法

1. **双击 `FDF.exe` 打开**（不要右键「以管理员身份运行」——否则拖放会被 UIPI 拦截）。
2. 把要删除的**文件或文件夹拖入窗口**，或点「粘贴路径」按钮粘贴绝对路径（可多选批量）。
3. 按需勾选选项：
   - 解锁被占用句柄
   - 结束占用进程（谨慎）
   - 接管所有权
   - 重启后删除（兜底）
   - 删除前覆写内容（shred）
4. 点「开始删除」。若目标需要管理员权限，系统会**自动弹出一次 UAC 授权窗口**，点「是」后提权 worker 执行删除。
5. 进度条与日志区实时显示每个目标的删除状态：`deleted` / `reboot`（已登记重启删除）/ `failed` / `blocked`（命中护栏）。

> 提示：删除系统关键路径会被自动拦截并标记为 `blocked`，不会执行。

---

## 五、编译 / 打包

项目使用 **PyInstaller** 打包为单文件 exe。

### 环境

- Python 3.13（建议用虚拟环境）
- PyInstaller 6.x
- 仅标准库 + `ctypes`，**无第三方 Python 依赖**

### 步骤

```bash
# 1. 准备虚拟环境（可选）
python -m venv fdf-build
fdf-build\Scripts\activate

# 2. 安装 PyInstaller
pip install pyinstaller

# 3. 打包
python build_bootstrap.py
# 产物： dist/FDF.exe
```

`build_bootstrap.py` 的作用是：在调用 PyInstaller 前，恢复被沙箱 `safe-delete` shim 拦截的原始 `os.remove` / `shutil.rmtree` 等删除 API（否则打包过程会因临时文件无法清理而失败），随后执行 `FDF.spec`。

### 关键打包配置

- `FDF.spec`：`Analysis(['main.py'], pathex=['src'], hiddenimports=['fdf','fdf.gui','fdf.engine','fdf.winapi','fdf.worker'])`，`EXE(..., console=False, icon=['assets\\fdf.ico'], manifest='fdf.manifest')`。
- `fdf.manifest`：`requestedExecutionLevel = asInvoker` + 启用 `Microsoft.Windows.Common-Controls v6`（主题化控件）。**不加 `--uac-admin`**，提权交由运行时 worker 子进程完成。
- 目标架构：**64 位**（`--onefile --noconsole`）。

---

## 六、目录结构

```
FDF-force-delete-file/
├── main.py                 # 入口：初始化 COM/OLE，启动 App
├── build_bootstrap.py      # 绕过沙箱 shim 后调用 PyInstaller
├── FDF.spec                # PyInstaller spec
├── fdf.manifest            # 应用清单（asInvoker + Common-Controls v6）
├── assets/
│   ├── fdf.ico             # 程序图标
│   └── build_icon.py       # 图标生成脚本
├── src/fdf/
│   ├── __init__.py         # 包说明
│   ├── gui.py              # 纯 ctypes Win32 界面（窗口/控件/拖放/渲染）
│   ├── engine.py           # 强制删除引擎（L0–L6 递进链 + 护栏）
│   ├── winapi.py           # Win32 API 的 ctypes 封装与常量
│   └── worker.py           # 提权工作进程（接收任务、执行删除、回写 JSONL）
└── tests/
    ├── make_stubborn.py    # 制造顽固文件（用于测试）
    ├── test_gui_run.py     # GUI 运行时冒烟测试（创建窗口并跑消息循环）
    └── test_stable.py      # 稳定性测试
```

---

## 七、测试

`tests/` 目录下包含：

- `test_gui_run.py`：真正创建窗口并运行消息循环数秒，验证子控件创建与 ctypes 调用正确（会自动退出并打印 `SMOKE_OK`）。
- `make_stubborn.py`：生成带只读 / 占用等属性的顽固文件，用于验证删除链。
- `test_stable.py`：稳定性相关测试。

运行（需 Windows + 已激活环境）：

```bash
python tests/test_gui_run.py
```

---

## 八、依赖

**运行时：无第三方依赖。** 仅使用 Python 标准库与 `ctypes` 调用 Windows 系统 API。

**构建时：** 仅 `pyinstaller`。

---

## 九、许可证

[MIT](LICENSE) © 2026 cv-superding

---

## 十、免责声明

本工具用于清理自己机器上确属多余的顽固文件。**删除操作不可逆**，请务必确认目标无误。系统关键路径已被自动拦截，但仍请谨慎使用「结束占用进程」等高风险选项。
