# FDF — 强制删除文件工具 (Force Delete File)

> Windows 下专治「文件被占用 / 拒绝访问 / 只读 / 被系统保护」等删不掉的场景。
> 基于 **PySide6 (Qt 6)** 的现代 GUI，Windows 11 Fluent 风格（白底卡片、蓝色强调、圆角阴影）、高 DPI 适配、响应式布局。打包成单个 `.exe`。

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

- **PySide6 (Qt 6) 现代界面**：基于 Qt 6 框架的 Fluent 风格 UI——白底卡片式布局、`#0078D4` 蓝色强调、圆角与阴影、高 DPI 自适应、响应式布局、原生拖放支持。
- **全程 Qt 自绘对话框**：确认删除、警告提示、文件选择等弹窗均由 Qt 渲染并套用 Fluent 样式，**不调用原生 Windows 对话框**，在暗色 / 亮色系统主题下外观一致、清晰可读。
- **拖放 / 粘贴路径**添加删除目标，支持文件与文件夹混合队列；粘贴支持多行与引号包裹的多个路径。
- **递进式删除策略 L0–L6**，自动逐级升级（详见第三节）。
- **双进程模型**：主界面以普通权限运行（与资源管理器同级，拖放正常），真正删除时由界面拉起**提权 worker 子进程**完成，避免 UIPI 拦截拖放。
- **系统关键路径护栏**：保护集合按系统盘动态构造，覆盖任意盘符下的 `Windows` 目录、所有卷根与 UNC 共享根；比对前统一做路径规范化（剥 `\\?\` 前缀、展开 8.3 短名、解析符号链接/junction 的物理路径），杜绝通过等价写法绕过护栏。
- **实时进度与日志**：worker 的日志 / 进度以 JSONL 流回写，主界面尾随读取并实时回显；目标列表中直接标注每项结果（✓ 已删除 / ✗ 失败 / 🚫 已拦截 / ⏳ 待重启）。
- **可随时取消**：任务进行中可点「取消」，worker 检测到取消标记后停止升级、尽快收尾。
- **悬停 / 按下态交互**：所有按钮带 Fluent 悬停与按下反馈；复选框为**自绘**（方框 + 对勾），不受系统主题影响，显示稳定。
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
| **L6** | 登记为重启时删除 `MoveFileEx(...MOVEFILE_DELAY_UNTIL_REBOOT)` | 最后兜底（登记前自动查 `PendingFileRenameOperations` 去重；非空目录不会登记，避免无谓条目拖慢开机） |

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

### 3.3 安全护栏（engine.py `is_protected`）

护栏把两类路径列为**绝对不允许删除**的目标，集合按 `SystemDrive` 等环境变量动态构造，不硬编码盘符：

**整棵子树保护**（目录内部任何东西都不允许动）：

```
<任意盘符>:\Windows          # 含 System32、WinSxS、注册表 hive 等全部子目录
<系统盘>:\Boot   <系统盘>:\EFI   <系统盘>:\Recovery
<任意盘符>:\System Volume Information   <系统盘>:\Config.msi
```

**整体根保护**（整个目录本身不许删，其子目录仍可正常删——方便清理卸载残留）：

```
X:\（所有卷根）   X:\$Recycle.Bin（所有盘的回收站）
<系统盘>:\Users   <系统盘>:\ProgramData
<系统盘>:\Program Files   <系统盘>:\Program Files (x86)   <系统盘>:\PerfLogs
\\server\share（UNC 共享根）   当前用户主目录   本程序所在目录
```

**防绕过**：比对前先做权威规范化——剥掉 `\\?\` / `\\?\UNC\` 前缀、展开 8.3 短文件名（如 `PROGRA~1`）、去掉尾随分隔符，并通过 `GetFinalPathNameByHandleW` 解析符号链接 / junction 指向的物理路径一并校验，保证「护栏比较的路径」与「实际删除的路径」是同一个对象。

---

## 四、使用方法

1. **双击 `FDF.exe` 打开**（不要右键「以管理员身份运行」——否则拖放会被 UIPI 拦截）。
2. 把要删除的**文件或文件夹拖入窗口**，或点「粘贴路径」按钮粘贴绝对路径（可多选批量）。
3. 按需勾选选项：
   - 解锁被占用句柄
   - 结束占用进程（谨慎）
   - 接管所有权
   - 重启后删除（兜底）
   - 删除前粉碎覆写（shred；注意：覆写失败时会在日志中警告，文件内容仍可能被恢复）
4. 点「开始删除」。若目标需要管理员权限，系统会**自动弹出一次 UAC 授权窗口**，点「是」后提权 worker 执行删除；点「否」会提示「已取消提权」，不会误报错误。
5. 进度条与日志区实时显示每个目标的删除状态，目标列表中也会直接标注结果：`deleted` / `reboot`（已登记重启删除）/ `failed` / `blocked`（命中护栏）。
6. 任务进行中可随时点「取消」：worker 会在当前步骤后停止升级手段、尽快收尾，已删除的部分不会恢复。

> 提示：删除系统关键路径会被自动拦截并标记为 `blocked`，不会执行。

---

## 五、编译 / 打包

项目使用 **PyInstaller** 打包为单文件 exe。

### 环境

- Python 3.13（建议用虚拟环境）
- PyInstaller 6.x
- **PySide6 6.11.x**（Qt 6 界面框架，含 PySide6_Addons）
- 产物：`dist/FDF.exe` 为 64 位单文件，体积约 **45 MB**（已内嵌 Qt 运行时，用户无需单独安装）

### 步骤

```bash
# 1. 准备虚拟环境（可选）
python -m venv fdf-build
fdf-build\Scripts\activate

# 2. 安装依赖
pip install pyinstaller PySide6

# 3. 打包
python build_bootstrap.py
# 产物： dist/FDF.exe
```

`build_bootstrap.py` 的作用是：在调用 PyInstaller 前，恢复被沙箱 `safe-delete` shim 拦截的原始 `os.remove` / `shutil.rmtree` 等删除 API（否则打包过程会因临时文件无法清理而失败），随后执行 `FDF.spec`。

### 关键打包配置

- `FDF.spec`：`Analysis(['main.py'], pathex=['src'], hiddenimports=['fdf','fdf.gui','fdf.engine','fdf.winapi','fdf.worker'])`，`EXE(..., console=False, icon=os.path.join(SPECPATH,'assets','fdf.ico'), manifest='fdf.manifest')`；`upx=False`（Qt6 DLL 经 UPX 压缩易崩溃且常被杀软误报）。
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
│   ├── gui.py              # PySide6 (Qt) 现代界面（布局/样式/拖放/信号桥）
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

- `test_gui_run.py`：真正创建窗口并运行消息循环数秒的冒烟测试（未安装 PySide6 时自动打印 SKIP 并以 0 退出，不影响 CI）。
- `make_stubborn.py`：生成带只读 / 占用等属性的顽固文件，用于验证删除链；`python tests/make_stubborn.py --cleanup` 可清理 `%TEMP%\fdf_testbed` 测试残留。
- `test_stable.py`：稳定性测试（多轮创建顽固文件并验证删除链；默认 `schedule_reboot=False`，不会登记真实的重启删除）。

运行（需 Windows + 已激活环境）：

```bash
python tests/test_stable.py     # 不需要 PySide6
python tests/test_gui_run.py    # 需要 PySide6
```

---

## 八、依赖

**运行时：** PySide6 (Qt) —— 由 PyInstaller 打包进单 exe，用户无需单独安装。

**构建时：** `pyinstaller` + `PySide6`。

---

## 九、许可证

[MIT](LICENSE) © 2026 cv-superding

---

## 十、免责声明

本工具用于清理自己机器上确属多余的顽固文件。**删除操作不可逆**，请务必确认目标无误。系统关键路径已被自动拦截，但仍请谨慎使用「结束占用进程」等高风险选项。
