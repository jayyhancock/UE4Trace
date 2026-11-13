# UE4Trace · UE4 事件观察器

面向 **自有或获得明确授权的 Android ARM64 应用** 的 ProcessEvent 观察工具。Windows 界面通过 ADB 连接手机，展示函数名称、对象、线程、耗时和同线程父调用链。

> 实验性项目。采集经过 ProcessEvent 的反射/蓝图分派，不是全部 C++ 调用图。原生 Hook 会改变目标进程代码，可能造成崩溃或不稳定。

## 公开版包含什么

- `desktop/`：PySide6 界面、ADB 操作、版本核验和有界 NDJSON 传输。
- `native/src/`：`ProcessEventTracer` 工具类、有界采集队列、名称解析与命令服务。
- `native/tests/`：自包含 ARM64 测试程序，可自行加载观察器，验证嵌套调用及原函数调用次数。
- `profiles/`：与特定 ELF Build ID 绑定的配置和参考偏移。
- `tests/`：不接触真实手机的后端测试，以及 `desktop/test_ui.py` 中的界面测试。

**公开版不包含远程注入器、预编译 Dobby 静态库、ADB 安装包、游戏二进制、真实采集日志或设备标识。** 原本地原型部分加载代码的再分发许可无法确认，因此未纳入仓库。公开版支持连接已经加载的观察器；需要自动加载时，必须自行提供有再分发/使用权限且满足 [加载器接口](docs/LOADER_CONTRACT.md) 的工具。

本次 GitHub 发布为源码版本，不发布原本地原型的 Windows ZIP。旧原型的采集库与公开版不是同一构建，不应混用。

## 快速开始：Windows 界面

需要 Python 3.13 和自行安装的 Android platform-tools。当前桌面连接流程要求手机已 root，并能通过 `su` 取得 UID 0；即使只连接已加载的观察器，也会执行这项检查。手机需完成 USB 调试和 root 授权。

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe launcher.py
```

仅离线查看 JSONL 时，以上步骤即可。连接手机前，还必须按 `native/README.md` 构建公开版原生组件，并准备相同构建的 manifest：

```powershell
New-Item -ItemType Directory -Force assets | Out-Null
Copy-Item native\build\artifacts\libue4trace.so,native\build\artifacts\native-manifest.json assets
```

缺失或无效的 manifest 会在任何设备操作之前被拒绝。不要复制旧原型的 manifest 来绕过验证。

1. 在界面选择 `adb.exe`，刷新并选择在线设备。
2. 选择与目标版本和 Build ID 完全对应的 JSON 配置，点击「检查版本」。
3. 由自有应用加载观察器，或自行配置合法且兼容的加载器，再点击「连接并准备」。
4. 从较低限速开始采集；点击记录查看原始字段和父调用链。
5. 暂停后可筛选、导出 JSONL/CSV，或打开已有 JSONL 离线查看。

未提供加载器且目标没有观察器时，程序会明确停止，不会自动下载或尝试其它注入方案。

## 构建原生组件与 Windows 包

原生组件使用 CMake、Ninja 和 Android NDK，面向 `arm64-v8a`。Dobby 和 nlohmann/json 从官方仓库的固定提交获取，不使用来源不明的预编译库。

详见 [原生构建与 fixture 测试](native/README.md)。编译原生组件后，可在 PowerShell 中运行：

```powershell
.\build_windows.ps1 -Python .\.venv\Scripts\python.exe `
  -NativeArtifacts .\native\build\artifacts
```

需要随本地构建附带 ADB 时，可另外指定 `-AdbDirectory`，并自行满足其再分发条件。没有指定时，在界面选择自己安装的 ADB。加载器同样是可选的本地输入，不由本仓库提供。

## 配置与记录语义

所有偏移都是相对模块 ELF load bias 的 **RVA**，不是可以跨进程复用的绝对地址，也不一定等于文件偏移。版本名、版本号、架构、Build ID、函数首 16 字节和名称表都必须通过验证。

仓库保留一份特定 `1.39.13 / ARM64` 构建的研究配置。它不构成对其它版本的支持承诺，也不表示维护者与相关游戏或引擎厂商存在关联。配置中 GObjects 是自定义结构的兼容定位点，不能按标准 GUObjectArray 套用。

- 事件在调用返回后发出，子事件可能先到；`call_id` / `parent_id` 只表达同一线程的嵌套关系。
- 耗时包含观测开销，不是精确性能基准。
- 名称异步读取，对象销毁或复用可能使名称失效。
- 手机队列上限 8,192 条，录入上限 1–10,000 条/秒；超限计入 dropped，名称过滤计入 filtered。
- 界面最多保留 20,000 条；导出的是当前筛选的保留记录，不是无限完整录制。
- 暂停、停止或断线会停止记录，但透传 Hook 保留到进程退出。程序不自动重启目标，也不更改 SELinux 或其它保护设置。
- 注入超时不能靠恢复寄存器保证回滚 loader 状态。未获得完整成功确认的进程会被持久标记，禁止重复尝试同一 PID/starttime。

## 测试

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m unittest desktop.test_ui -v
.\.venv\Scripts\python.exe tools/check_public_tree.py
```

测试范围与已知限制见 [验证说明](docs/VALIDATION.md)。当前 GitHub Actions 自动运行源码发布检查和桌面测试；原生构建/真机 fixture 需要按文档单独运行，尚未纳入 CI。构建通过不等于适用于任意应用，也不代表长期运行稳定性。

## 开源与协作

原创代码采用 [MIT License](LICENSE)，允许在保留许可声明的条件下使用、修改、分发和商业使用。第三方依赖保留各自许可，见 [第三方声明](THIRD_PARTY_NOTICES.md)。

- [贡献规则](CONTRIBUTING.md)
- [行为准则](CODE_OF_CONDUCT.md)
- [安全问题报告](SECURITY.md)
- [免责声明与使用边界](DISCLAIMER.md)

免责声明、维护范围和贡献规则不为 MIT 许可证额外增加用途或商业限制。
