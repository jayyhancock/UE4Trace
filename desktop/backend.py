"""ADB deployment and bounded NDJSON transport for the UE4 event observer.

This module has no Qt dependency. All operations are explicit and blocking except
for socket reception; the UI runs the public methods on its worker thread.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shlex
import socket
import struct
import subprocess
import tempfile
import threading
import time
from typing import Callable, Any

MAX_LINE = 256 * 1024


class TraceError(RuntimeError):
    pass


class AdbCommandError(TraceError):
    def __init__(self, message: str, *, returncode=None, output='', timed_out=False):
        super().__init__(message)
        self.returncode = returncode
        self.output = output
        self.timed_out = timed_out


class TargetStateStore:
    """Fail closed across client/app restarts after an uncertain injection."""
    _lock = threading.Lock()

    def __init__(self, path: Path | None = None):
        base = Path(os.environ.get('LOCALAPPDATA') or (Path.home() / 'AppData' / 'Local'))
        self.path = path or base / 'UE4Trace' / 'target-state.json'

    @staticmethod
    def identity(serial: str, info: dict) -> dict:
        pid = int(info['pid'])
        starttime = str(info['starttime'])
        if pid <= 0 or not starttime.isdigit():
            raise TraceError('无法确认目标进程身份；不会执行注入。')
        return dict(serial=str(serial), package=str(info['package']), pid=pid, starttime=starttime)

    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            if self.path.stat().st_size > 256 * 1024:
                raise ValueError('size')
            value = json.loads(self.path.read_text(encoding='utf-8'))
            if not isinstance(value, list) or len(value) > 128:
                raise ValueError('records')
            for row in value:
                if not isinstance(row, dict) or not all(k in row for k in ('serial','package','pid','starttime')):
                    raise ValueError('identity')
                self.identity(row['serial'], row)
            return value
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise TraceError('本机目标状态记录无法读取；为避免重复注入，连接已停止。') from exc

    def _save(self, rows: list[dict]):
        temporary = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix='target-state-', suffix='.tmp', dir=self.path.parent)
            temporary = Path(name)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(rows, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            raise TraceError('无法持久保存目标状态；为避免注入后无法保护重试，操作已停止。') from exc
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    @staticmethod
    def _same(row: dict, identity: dict) -> bool:
        return all(str(row.get(key)) == str(value) for key, value in identity.items())

    def check(self, serial: str, info: dict):
        identity = self.identity(serial, info)
        with self._lock:
            rows = self._load()
            if any(self._same(row, identity) for row in rows):
                raise TraceError(f'PID {identity["pid"]}（starttime {identity["starttime"]}）注入状态不确定；'
                                 '已禁止对同一进程重试。请自行重新打开游戏后连接，程序不会结束或重启游戏。')

    def begin(self, serial: str, info: dict):
        identity = self.identity(serial, info)
        with self._lock:
            rows = self._load()
            if any(self._same(row, identity) for row in rows):
                raise TraceError('同一目标进程已有未确认的注入记录，已禁止重试。')
            # A uniquely inspected new process replaces a stale identity for the
            # same selected package/device; never silently evict other targets.
            rows = [row for row in rows if (row['serial'], row['package']) != (identity['serial'], identity['package'])]
            if len(rows) >= 128:
                raise TraceError('本机目标状态记录已满；未执行注入。')
            rows.append(dict(identity, reason='injection_started_without_confirmation'))
            self._save(rows)

    def clear(self, serial: str, info: dict):
        identity = self.identity(serial, info)
        with self._lock:
            rows = self._load()
            remaining = [row for row in rows if not self._same(row, identity)]
            if len(remaining) != len(rows):
                self._save(remaining)


def shell_quote(value: str) -> str:
    return shlex.quote(str(value))


def parse_maps(text: str, module: str) -> dict[str, Any]:
    entries = []
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or Path(fields[5].replace(' (deleted)', '')).name != module:
            continue
        lo, hi = (int(x, 16) for x in fields[0].split('-'))
        entries.append(dict(start=lo, end=hi, perms=fields[1], offset=int(fields[2], 16), path=fields[5]))
    zero = [e for e in entries if e['offset'] == 0]
    if len(zero) != 1:
        raise TraceError(f'无法唯一定位 {module} 加载基址；请等游戏加载完成后重试。')
    return dict(base=zero[0]['start'], path=zero[0]['path'], entries=entries)


def parse_build_id_notes(data: bytes) -> str:
    pos = 0
    while pos + 12 <= len(data):
        namesz, descsz, kind = struct.unpack_from('<III', data, pos)
        pos += 12
        if namesz > len(data)-pos:
            break
        name = data[pos:pos+namesz]
        pos += (namesz+3) & ~3
        if descsz > len(data)-pos:
            break
        desc = data[pos:pos+descsz]
        pos += (descsz+3) & ~3
        if name.rstrip(b'\0') == b'GNU' and kind == 3:
            return desc.hex()
    return ''


class AdbBridge:
    def __init__(self, adb_path: str | Path):
        self.adb_path = str(adb_path)

    def run(self, args: list[str], timeout: float = 20, binary: bool = False,
            check: bool = True) -> str | bytes:
        try:
            result = subprocess.run([self.adb_path, *map(str, args)], capture_output=True,
                timeout=timeout, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except FileNotFoundError as e:
            raise TraceError('未找到 adb.exe；请在界面选择 Android platform-tools 中的 ADB。') from e
        except subprocess.TimeoutExpired as e:
            raise AdbCommandError('ADB 操作超时；请检查 USB 连接、手机调试授权或 root 授权。', timed_out=True) from e
        if check and result.returncode:
            err = result.stderr.decode('utf-8', 'replace').strip()
            out = result.stdout.decode('utf-8', 'replace').strip()
            output = '\n'.join(part for part in (out, err) if part)
            raise AdbCommandError(f'ADB 操作失败（{result.returncode}）：{output}',
                                  returncode=result.returncode, output=output)
        return result.stdout if binary else result.stdout.decode('utf-8', 'replace').strip()

    def list_devices(self) -> list[dict[str, str]]:
        output = self.run(['devices', '-l'])
        devices = []
        for line in str(output).splitlines():
            fields = line.split()
            if len(fields) < 2 or fields[0] == 'List' or fields[0].startswith('*'):
                continue
            model = next((x[6:] for x in fields[2:] if x.startswith('model:')), '')
            devices.append(dict(serial=fields[0], state=fields[1], model=model))
        return devices

    def shell(self, serial: str, command: str, root: bool = False,
              timeout: float = 20, binary: bool = False) -> str | bytes:
        args = ['-s', serial, 'exec-out' if binary else 'shell']
        # exec-out passes argv directly, while shell parses a joined shell line.
        args += ['su', '-c', command if binary else shell_quote(command)] if root else [command]
        return self.run(args, timeout=timeout, binary=binary)

    def read_file_range(self, serial: str, path: str, offset: int, length: int) -> bytes:
        if offset < 0 or not 0 < length <= 256*1024:
            raise TraceError('ELF 元数据读取范围无效。')
        base = offset & ~4095
        count = (offset+length-base+4095)//4096
        cmd = f'dd if={shell_quote(path)} bs=4096 skip={base//4096} count={count} status=none'
        data = self.shell(serial, cmd, root=True, binary=True)
        assert isinstance(data, bytes)
        result = data[offset-base:offset-base+length]
        if len(result) != length:
            raise TraceError('未完整读取 ELF 元数据；目标文件可能已更新。')
        return result

    def build_id(self, serial: str, path: str) -> str:
        head = self.read_file_range(serial, path, 0, 64)
        if head[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', head, 18)[0] != 183:
            raise TraceError('目标模块不是 ARM64 little-endian ELF。')
        phoff = struct.unpack_from('<Q', head, 32)[0]
        size, count = struct.unpack_from('<HH', head, 54)
        if size != 56 or not 0 < count <= 128:
            raise TraceError('ELF 程序头异常。')
        table = self.read_file_range(serial, path, phoff, size*count)
        for n in range(count):
            kind, flags, offset, va, pa, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ',table,n*size)
            if kind == 4 and 0 < filesz <= 256*1024:
                found = parse_build_id_notes(self.read_file_range(serial,path,offset,filesz))
                if found:
                    return found
        raise TraceError('目标模块没有可验证的 GNU Build ID；连接已停止。')


class PhoneTraceClient:
    def __init__(self, adb_path: str | Path, serial: str, assets_dir: str | Path,
                 profile_path: str | Path, on_message: Callable[[dict],None] | None = None,
                 on_log: Callable[[str],None] | None = None):
        self.adb = AdbBridge(adb_path)
        self.serial = serial
        self.assets = Path(assets_dir)
        self.profile_path = Path(profile_path)
        self.on_message = on_message or (lambda message: None)
        self.on_log = on_log or (lambda message: None)
        self.profile = json.loads(self.profile_path.read_text(encoding='utf-8-sig'))
        self._validate_profile()
        self.info: dict = {}
        self.sock: socket.socket | None = None
        self.port: int | None = None
        self._reader: threading.Thread | None = None
        self._closed = threading.Event()
        self._send_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[int,queue.Queue] = {}
        self._next_id = 0
        self._hello = threading.Event()
        self._hello_message: dict = {}
        self._target_states = TargetStateStore()

    def _validate_profile(self):
        p = self.profile
        if p.get('schema_version') != 1 or p.get('abi') != 'arm64-v8a':
            raise TraceError('偏移配置格式或架构不受支持。')
        if not re.fullmatch(r'[a-zA-Z0-9_.]+', str(p.get('package',''))):
            raise TraceError('配置包名无效。')
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', str(p.get('module',''))):
            raise TraceError('配置模块名无效。')
        if not re.fullmatch(r'[0-9a-fA-F]{16,128}', str(p.get('build_id',''))):
            raise TraceError('配置必须包含已核验的 ELF Build ID。')
        prologue=str(p.get('process_event_prologue','')).replace(' ','').lower()
        if not re.fullmatch(r'[0-9a-f]{32}', prologue):
            raise TraceError('配置必须包含 ProcessEvent 的准确首 16 字节。')
        p['process_event_prologue']=prologue
        if not str(p.get('version_name','')) or not str(p.get('version_code','')).isdigit():
            raise TraceError('配置必须包含 version_name 和 version_code。')
        layout=p.get('layout')
        if not isinstance(layout,dict) or layout.get('name_kind') not in ('legacy','pool'):
            raise TraceError('配置缺少有效名称表布局。')
        required_ranges={'names_indirect':(0,2),'object_name':(0,256),
            'object_class':(0,256),'object_outer':(0,256),'function_flags':(0,1024)}
        optional_ranges={'chunk_size':(1024,65536),'name_entry_string':(0,128),
            'name_entry_header':(0,128),'pool_blocks':(0,1024),
            'pool_block_bits':(8,20),'pool_length_shift':(0,10)}
        for key,(lo,hi) in dict(required_ranges,**optional_ranges).items():
            if key not in layout and key in optional_ranges:
                continue
            val=layout.get(key)
            if type(val) is not int or not lo<=val<=hi:
                raise TraceError(f'配置布局字段无效：{key}')
        for key in ('process_event','gnames','gobjects','gactivity'):
            try:
                value = int(str(p['offsets'][key]),0)
            except (KeyError,ValueError,TypeError) as e:
                raise TraceError(f'配置缺少有效偏移：{key}') from e
            if not 0 < value < (1<<40):
                raise TraceError(f'偏移超出范围：{key}')

    def _emit(self, message: dict):
        try:
            self.on_message(message)
        except Exception:
            pass  # A UI callback must never strand transport response waiters.

    def _log(self, message: str):
        try:
            self.on_log(message)
        except Exception:
            pass

    def inspect(self) -> dict:
        state = next((d for d in self.adb.list_devices() if d['serial']==self.serial),None)
        if not state or state['state']!='device':
            raise TraceError('设备未连接或尚未授权；请在手机确认 USB 调试。')
        root = str(self.adb.shell(self.serial,'id',root=True))
        if 'uid=0(' not in root:
            raise TraceError('需要手机 root 读取与注入权限；请确认 su 授权。')
        p = self.profile
        package = p['package']
        details = str(self.adb.shell(self.serial,f'dumpsys package {shell_quote(package)}'))
        def field(pattern):
            m=re.search(pattern,details)
            return m.group(1) if m else ''
        version = field(r'\bversionName=([^\s]+)')
        version_code = field(r'\bversionCode=(\d+)')
        abi = field(r'\bprimaryCpuAbi=([^\s]+)')
        pid_text = str(self.adb.shell(self.serial,f'pidof {shell_quote(package)}')).strip()
        if not re.fullmatch(r'\d+',pid_text):
            raise TraceError('未找到唯一游戏主进程；请先启动配置对应的游戏。')
        pid=int(pid_text)
        maps=str(self.adb.shell(self.serial,f'cat /proc/{pid}/maps',root=True))
        module = parse_maps(maps,p['module'])
        if module['path'].endswith(' (deleted)'):
            raise TraceError('模块文件已更新但进程尚未重启；请自行重启游戏后重试。')
        build_id=self.adb.build_id(self.serial,module['path'])
        match = (version==str(p['version_name']) and version_code==str(p['version_code'])
                 and abi==p['abi'] and build_id.lower()==p['build_id'].lower())
        stat=str(self.adb.shell(self.serial,f'cat /proc/{pid}/stat',root=True))
        # comm can contain spaces; fields after closing ')' begin with field 3.
        starttime=stat.rsplit(')',1)[1].split()[19]
        info=dict(package=package,version_name=version,version_code=version_code,
            pid=pid,abi=abi,base=hex(module['base']),module_path=module['path'],
            build_id=build_id,profile_match=match,starttime=starttime,
            resident_observer=any('libue4trace' in l for l in maps.splitlines()))
        self.info=info
        self._log(f'设备检查：{package} {version} / {abi} / PID {pid} / 基址 {info["base"]}')
        return info

    def _forward(self):
        if self.port is None:
            result=self.adb.run(['-s',self.serial,'forward','tcp:0',f'localabstract:ue4trace_{self.info["pid"]}'])
            if not str(result).isdigit():
                raise TraceError('ADB 未返回有效转发端口。')
            self.port=int(str(result))

    def _expected_manifest(self) -> dict:
        manifest = self.assets / 'native-manifest.json'
        try:
            expected = json.loads(manifest.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError, UnicodeError) as exc:
            raise TraceError('缺少或无法读取 assets/native-manifest.json；请先构建并准备采集库产物。'
                             '未连接设备，也不会执行注入。') from exc
        compatible = expected.get('compatible_resident_builds', []) if isinstance(expected, dict) else None
        if (not isinstance(expected, dict) or type(expected.get('protocol')) is not int
                or expected['protocol'] != 1
                or not isinstance(expected.get('agent_build'), str)
                or re.fullmatch(r'[0-9a-f]{64}', expected['agent_build']) is None
                or not isinstance(compatible, list)
                or any(not isinstance(build, str) or re.fullmatch(r'[0-9a-f]{64}', build) is None
                       for build in compatible)):
            raise TraceError('assets/native-manifest.json 格式无效：需要协议 1 和完整构建哈希；未连接设备或执行注入。')
        return expected

    def _try_socket(self, *, reuse_resident: bool = False) -> bool:
        expected = self._expected_manifest()
        self._hello.clear()
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(('127.0.0.1',self.port))
        except OSError:
            s.close()
            return False
        try:
            data=bytearray()
            while b'\n' not in data and len(data)<=MAX_LINE:
                chunk=s.recv(8192)
                if not chunk:
                    if not data:
                        s.close()
                        return False  # ADB closes the forwarded connection if no listener exists.
                    raise TraceError('采集端握手不完整；拒绝重复注入。')
                data.extend(chunk)
            if len(data)>MAX_LINE:
                raise TraceError('采集端 hello 超出协议限制。')
            first,remaining=bytes(data).split(b'\n',1)
            try:
                hello=json.loads(first)
                if not isinstance(hello,dict):
                    raise ValueError('hello is not an object')
                hello_pid=int(hello.get('pid',0))
            except (ValueError,TypeError) as e:
                raise TraceError('采集端握手格式错误；拒绝重复注入。') from e
            if hello.get('type')!='hello' or hello.get('protocol')!=1 or hello_pid!=self.info['pid']:
                raise TraceError('采集端握手版本或进程身份不匹配。')
            if hello.get('agent_build')!=expected['agent_build']:
                compatible = expected.get('compatible_resident_builds', [])
                allowed = (reuse_resident and hello.get('hook_installed') is True
                           and isinstance(hello.get('agent_build'), str)
                           and hello['agent_build'] in compatible)
                if not allowed:
                    raise TraceError('目标进程驻留的是未允许复用的采集库构建；连接已停止。')
                self._log(f'正在复用已安装 Hook 的兼容驻留构建 {hello["agent_build"]}；'
                          '不会再次注入，将由 configure 核对相同配置。')
            self._hello_message=hello
            self._hello.set()
            s.settimeout(1)
            self.sock=s
            self._closed.clear()
            self._reader=threading.Thread(target=self._receive,args=(remaining,),name='ue4trace-reader',daemon=True)
            self._reader.start()
            self._emit(hello)
            return True
        except OSError as e:
            s.close()
            raise TraceError('采集端握手超时或连接失败；请关闭其它采集连接后重试，已停止重复注入。') from e
        except Exception:
            s.close()
            raise

    def connect(self) -> dict:
        if self.sock:
            raise TraceError('已经连接；请先断开当前采集。')
        injection_started = False
        before = None
        try:
            self._expected_manifest()
            before=self.inspect()
            if not before['profile_match']:
                raise TraceError('游戏版本、架构或 Build ID 与配置不符；拒绝使用过期偏移。')
            self._target_states.check(self.serial, before)
            self._forward()
            if not self._try_socket(reuse_resident=bool(before.get('resident_observer'))):
                if before.get('resident_observer'):
                    raise TraceError('进程已有采集库但未能握手；请检查其它连接或自行重启游戏，已停止重复注入。')
                inject=self.assets/'inject'
                library=self.assets/'libue4trace.so'
                if not inject.is_file():
                    raise TraceError('公开版不附带加载器，当前进程尚未加载观察器。'
                                     '请自备具有适用许可证且兼容调用约定的 loader，放置为 assets/inject；'
                                     '或由自有 Android app 加载采集库后再连接。')
                if not library.is_file():
                    raise TraceError('assets 缺少 libue4trace.so；请先构建采集库并通过 NativeArtifacts 打包。')
                digest=hashlib.sha256(library.read_bytes()).hexdigest()[:16]
                remote_dir='/data/local/tmp/ue4trace'
                remote_inject=f'{remote_dir}/inject'
                remote_stage=f'{remote_dir}/libue4trace-{digest}.so'
                private_dir=f'/data/user/0/{before["package"]}/files/ue4trace'
                remote_so=f'{private_dir}/libue4trace-{digest}.so'
                self.adb.shell(self.serial,f'mkdir -p {shell_quote(remote_dir)} && chown 2000:2000 {shell_quote(remote_dir)} && chmod 750 {shell_quote(remote_dir)}',root=True)
                self.adb.run(['-s',self.serial,'push',str(inject),remote_inject],timeout=40)
                self.adb.run(['-s',self.serial,'push',str(library),remote_stage],timeout=40)
                cmd=(f'chmod 755 {shell_quote(remote_inject)} && mkdir -p {shell_quote(private_dir)} && '
                     f'cp {shell_quote(remote_stage)} {shell_quote(remote_so)} && chmod 755 {shell_quote(remote_so)} && '
                     f'restorecon {shell_quote(private_dir)} {shell_quote(remote_so)}')
                self.adb.shell(self.serial,cmd,root=True)
                after=self.inspect()
                if not after['profile_match'] or any(after[k]!=before[k] for k in ('pid','starttime','base','build_id')):
                    raise TraceError('部署期间游戏进程发生变化；请重新连接。')
                self._log('正在加载采集库；成功握手并校验代码后才安装 Hook。')
                cmd=f'{shell_quote(remote_inject)} {before["pid"]} {shell_quote(remote_so)} --path-only'
                # Persist before entering ADB so application termination or an
                # interrupted wait cannot reopen an automatic reinjection path.
                self._target_states.begin(self.serial, before)
                injection_started = True
                output=str(self.adb.shell(self.serial,cmd,root=True,timeout=45))
                self._log(output[-12000:])
                if 'TARGET_STATE_UNCERTAIN' in output:
                    raise TraceError('注入器报告 TARGET_STATE_UNCERTAIN；已禁止同一进程重试。')
                for attempt in range(10):
                    if self._try_socket():
                        break
                    time.sleep(.3)
                else:
                    raise TraceError('加载命令结束但采集端未握手；请查看注入日志，不要重复安装 Hook。')
            result=self._command('configure',profile=self.profile,timeout=20)
            if injection_started:
                self._target_states.clear(self.serial, before)
            self._log('采集端已连接并配置，等待点击开始采集。')
            return dict(self.info,agent=self._hello_message,configured=result)
        except BaseException:
            if injection_started:
                self._log(f'PID {before["pid"]}（starttime {before["starttime"]}）注入尚未获得完整成功确认；'
                          '已持久标记状态不确定，同一进程不会自动重试。')
            self._shutdown_transport()
            raise

    def _receive(self, initial: bytes=b''):
        pending=bytearray(initial)
        failure=''
        s=self.sock
        try:
            while not self._closed.is_set():
                while b'\n' in pending:
                    line,rest=pending.split(b'\n',1)
                    pending=bytearray(rest)
                    if len(line)>MAX_LINE:
                        raise TraceError('采集端消息超过长度限制。')
                    if not line:
                        continue
                    message=json.loads(line)
                    if not isinstance(message,dict):
                        raise TraceError('采集端消息格式错误。')
                    rid=message.get('request_id')
                    with self._pending_lock:
                        waiter=self._pending.get(rid)
                    if waiter is not None:
                        try:
                            waiter.put_nowait(message)
                        except queue.Full:
                            pass
                    self._emit(message)
                if len(pending)>MAX_LINE:
                    raise TraceError('采集端消息超过长度限制。')
                try:
                    block=s.recv(64*1024)
                except socket.timeout:
                    continue
                if not block:
                    raise TraceError('采集端已断开；游戏可能退出或重启。')
                pending.extend(block)
        except Exception as e:
            failure=str(e)
        finally:
            unexpected=not self._closed.is_set()
            self._closed.set()
            with self._pending_lock:
                for waiter in self._pending.values():
                    try:
                        waiter.put_nowait({'type':'error','ok':False,'message':failure or '连接已关闭'})
                    except queue.Full:
                        pass
            if unexpected:
                self._shutdown_transport()
                self._log(failure)
                self._emit({'type':'disconnected','message':failure})

    def _command(self, cmd: str, timeout: float=8, **fields) -> dict:
        if self.sock is None or self._closed.is_set():
            raise TraceError('未连接采集端。')
        with self._send_lock:
            self._next_id+=1
            rid=self._next_id
            waiter=queue.Queue(maxsize=1)
            with self._pending_lock:
                self._pending[rid]=waiter
            message=dict(cmd=cmd,request_id=rid,**fields)
            data=(json.dumps(message,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8')
            if len(data)>MAX_LINE:
                with self._pending_lock:
                    self._pending.pop(rid,None)
                raise TraceError('配置超过协议大小限制。')
            try:
                self.sock.sendall(data)
            except OSError as e:
                with self._pending_lock:
                    self._pending.pop(rid,None)
                self._shutdown_transport()
                self._emit({'type':'disconnected','message':'命令发送失败，已关闭连接并停止采集。'})
                raise TraceError('发送命令失败；请重新连接。') from e
        try:
            response=waiter.get(timeout=timeout)
            if response.get('type')=='error' or response.get('ok') is False:
                raise TraceError(str(response.get('message') or response.get('error') or '采集端操作失败。'))
            return response
        except queue.Empty as e:
            self._shutdown_transport()
            self._emit({'type':'disconnected','message':f'{cmd} 未获确认，已关闭连接以停止采集。'})
            raise TraceError(f'采集端未确认 {cmd}；请检查诊断日志。') from e
        finally:
            with self._pending_lock:
                self._pending.pop(rid,None)

    def start(self, include: str='', exclude: str='', max_rate: int=1000):
        if not 1<=int(max_rate)<=10000:
            raise TraceError('每秒事件上限必须在 1–10000。')
        if len(include.encode('utf-8'))>256 or len(exclude.encode('utf-8'))>256:
            raise TraceError('筛选文本不能超过 256 字节。')
        return self._command('start',include=include,exclude=exclude,max_rate=int(max_rate))

    def pause(self):
        return self._command('pause')

    def status(self):
        return self._command('status')

    def _shutdown_transport(self):
        self._closed.set()
        s,self.sock=self.sock,None
        if s:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
        if self._reader and self._reader is not threading.current_thread():
            self._reader.join(timeout=2)
        self._reader=None
        if self.port is not None:
            port,self.port=self.port,None
            try:
                self.adb.run(['-s',self.serial,'forward','--remove',f'tcp:{port}'],timeout=5)
            except Exception as e:
                self._log(f'清理转发提示：{e}')

    def disconnect(self):
        try:
            if self.sock and not self._closed.is_set():
                self._command('stop',timeout=3)
        except Exception as e:
            self._log(f'停止确认：{e}；关闭连接后采集端也会停止记录。')
        finally:
            self._shutdown_transport()
            self._emit({'type':'disconnected','message':'已断开；采集已停止，Hook 保留透传。'})
