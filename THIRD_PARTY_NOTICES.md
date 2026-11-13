# 第三方来源与许可

根目录 MIT 许可证适用于本仓库原创代码，不重新授权第三方材料、目标应用或品牌。

| 组件 | 固定来源 / 版本 | 许可与处理方式 |
|---|---|---|
| Dobby | `jmpews/Dobby`，提交 `b0176de574104726bb68dff3b77ee666300fc338` | Apache-2.0；构建时从官方源码获取，许可原文见 `licenses/Dobby-Apache-2.0.txt` |
| Dobby 内含 TinySTL | 同一固定 Dobby 提交的第三方组件 | 保留上游 BSD 版权与免责文本，见 `licenses/Dobby-TinySTL-BSD.txt` |
| Dobby 内含 LLVM 来源代码 | 同一固定 Dobby 提交的相关源码 | Apache-2.0 WITH LLVM-exception；许可及例外见 `licenses/LLVM-Apache-2.0-with-exception.txt`，源码文件内的版权声明继续适用 |
| nlohmann/json | `nlohmann/json`，提交 `55f93686c01528224f448c19128836e7df245f72`（v3.12.0） | MIT；构建时从官方源码获取，许可原文见 `licenses/nlohmann-json-MIT.txt` |
| PySide6 / Qt | Python 依赖见 `requirements.txt` | 遵循上游 LGPL/GPL/商业许可组合；本仓库不分发其运行库 |
| PyInstaller | Python 构建依赖见 `requirements.txt` | 遵循上游许可和 bootloader 例外；不将其代码重新标记为 MIT |
| CPython | 用户自行安装的 Python 3.13 | 遵循 Python Software Foundation 等随分发提供的许可 |
| Android platform-tools / ADB | 用户自行安装或提供 | 本仓库不附带 ADB 二进制；再次分发时须自行核对随附条款 |

## 从本地原型中排除的内容

本地原型参考过 LuaHookStandalone / PubgMaoerInjection 的远程加载实现和预编译 Dobby 静态库。由于这些具体副本的来源链与再分发许可未完成核验，**其注入器源文件、头文件及静态库均没有收入本仓库**。此说明不是对这些外部项目作出的许可或违法性判断。

AndUE4DumpTools 曾作为结构研究参考；本仓库没有复制其 dumper、xDL、LSPlt 或反汇编器实现。静态偏移属于特定模块构建的研究配置，不授予对第三方游戏内容的权利。

构建本地 Windows 包或再次分发原生库时，应同时遵守实际随包组件的许可与声明要求；根目录 MIT 许可不会免除这些独立义务。

上游来源：

- https://github.com/jmpews/Dobby
- https://github.com/nlohmann/json
- https://doc.qt.io/qtforpython-6/licenses.html
- https://pyinstaller.org/en/stable/license.html
- https://developer.android.com/tools/releases/platform-tools
