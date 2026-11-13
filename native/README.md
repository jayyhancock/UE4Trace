# 原生构建与独立 fixture 测试

以下命令在仓库根目录运行。需要 Android NDK、CMake 3.22 或更新版本、Ninja，以及可连接 ARM64 Android 设备的 ADB。首次配置会从官方仓库下载固定提交的 Dobby 和 nlohmann/json，CMake 同时校验下载归档的 SHA-256。

## 构建

把 `ANDROID_NDK_HOME` 设置为自己的 NDK 安装目录，并让 `cmake`、`ninja` 和 `adb` 可从 PATH 调用。本次验证使用 NDK `28.2.13676358`、CMake `3.22.1`、Android API 24 和 `c++_static`：

```powershell
cmake -S native -B native/build -G Ninja `
  "-DCMAKE_TOOLCHAIN_FILE=$env:ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" `
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 `
  -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
cmake --build native/build --target ue4trace ue4trace_fixture -j 4
```

输出位于 `native/build/artifacts/`：

| 文件 | 用途 |
|---|---|
| `libue4trace.so` | 观察器；加载后启动 socket，configure 验证通过后才安装 Hook |
| `native-manifest.json` | 该构建的版本、协议和身份；与采集库一起提供给桌面端 |
| `ue4trace_fixture` | 自包含测试进程，可自行加载观察器 |
| `libue4trace_fixture_module.so` | fixture 的嵌套调用与模拟对象模块 |

观察器版本为 `0.1.0`，协议版本为 `1`。构建身份包含观察器源码、头文件、CMake 文件、依赖提交和编译器版本；它不是可复现二进制的哈希证明。更换依赖、工具链或源码后应重新构建和验证，并同步更新桌面端的库与 manifest。不要手工修改 manifest 或添加兼容身份来跳过验证。

项目不构建或提供远程注入器。外部加载器契约见 [LOADER_CONTRACT.md](../docs/LOADER_CONTRACT.md)。第三方许可及其子组件声明见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

## 在独立进程中验证

fixture 不连接游戏；它运行自己的两层嵌套调用，通过 `dlopen` 加载本次构建的观察器。生成的 profile 描述的是独立可执行进程，仅用于下面的 socket 测试，不是桌面端 Android 应用包检查流程的配置。

只有一台设备时可直接使用 `adb`；多设备时，在每条命令中加入同一组 `-s <serial>` 参数。测试应使用专用临时目录，不覆盖其它应用或正在运行的测试。

在第一个 PowerShell 终端中部署并启动：

```powershell
$fixtureRemote = '/data/local/tmp/ue4trace_fixture_' + [Guid]::NewGuid().ToString('N')
$fixtureRemote  # 记下此值，第二个终端和清理时需要
adb shell mkdir -p $fixtureRemote
adb push native/build/artifacts/ue4trace_fixture "$fixtureRemote/"
adb push native/build/artifacts/libue4trace_fixture_module.so "$fixtureRemote/"
adb push native/build/artifacts/libue4trace.so "$fixtureRemote/"
adb shell chmod 755 "$fixtureRemote/ue4trace_fixture"
adb shell "cd '$fixtureRemote' && LD_LIBRARY_PATH='$fixtureRemote' ./ue4trace_fixture '$fixtureRemote/profile.json' '$fixtureRemote/libue4trace.so'"
```

保持该终端打开。输出中的 `fixture pid=... ready` 给出本次 fixture 的 PID。运行期间会报告 `PASS ticks=... original_calls=...`；每个 tick 必须恰好执行两次原函数。若设备不允许执行或加载，先检查设备自身的调试条件，本项目不会自动更改其安全策略。

在第二个 PowerShell 终端中输入刚才的目录和 PID，再建立只属于该 fixture 的端口转发：

```powershell
$fixtureRemote = Read-Host '输入第一个终端显示的 fixture 临时目录'
$fixtureProcessId = [int](Read-Host '输入本次 fixture PID')
New-Item -ItemType Directory -Force native/build/fixture-check | Out-Null
adb pull "$fixtureRemote/profile.json" native/build/fixture-check/profile.json
$fixturePort = (adb forward tcp:0 "localabstract:ue4trace_$fixtureProcessId").Trim()
py -3.13 native/tests/fixture_protocol.py $fixturePort native/build/fixture-check/profile.json
```

脚本验证错误 Build ID、错误函数前导字节、幂等 configure、配置变更拒绝、事件名称、唯一调用 ID、同线程父子关系、暂停、过滤、停止及重新连接后的状态。应看到 `passed: true`；首次运行还应为 `fresh_hook_install: true`。事件条数受调度影响，不要求每次与发布验证记录完全相同。

测试后停止自己启动的 fixture，检查第一个终端的 `FINAL` 行中 `original_calls == expected == ticks * 2`。确认它已退出后，再删除本次转发与临时目录：

```powershell
adb shell kill -TERM $fixtureProcessId
# 确认第一个终端已退出，且 FINAL 计数相符，再继续：
adb forward --remove "tcp:$fixturePort"
adb shell rm -r $fixtureRemote
```

不要使用全局移除转发或按进程名批量终止命令。测试输出和 profile 含运行时地址及进程信息，应留在被忽略的本地构建目录，不提交到公开仓库。

## 验证范围

发布前的具体结果见 [VALIDATION.md](../docs/VALIDATION.md)。fixture 证明被测构建在该测试中的行为，不能证明任意目标应用兼容、长时间稳定、完整覆盖原生调用，或停止后已卸载 Hook。当前 GitHub CI 只自动运行源码检查与桌面测试，不包含 NDK 构建或真机测试。
