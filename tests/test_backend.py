import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from desktop.backend import AdbBridge, AdbCommandError, PhoneTraceClient, TargetStateStore, TraceError, parse_maps, parse_build_id_notes


PROFILE = dict(schema_version=1,package='example.fixture',version_name='1',version_code=1,
    abi='arm64-v8a',module='libUE4.so',build_id='ab'*20,process_event_prologue='00'*16,
    offsets=dict(process_event='0x100',gnames='0x200',gobjects='0x300',gactivity='0x400'),
    layout=dict(name_kind='legacy',names_indirect=1,object_name=24,object_class=16,object_outer=32,function_flags=136))


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path=Path(self.tmp.name)/'profile.json'
        path.write_text(json.dumps(PROFILE),encoding='utf-8')
        (Path(self.tmp.name)/'native-manifest.json').write_text(
            json.dumps({'protocol':1,'agent_build':'ad'*32}),encoding='utf-8')
        self.messages=[]
        self.client=PhoneTraceClient('adb','serial',self.tmp.name,path,self.messages.append)
        self.client.adb=Mock()
        self.client._target_states=TargetStateStore(Path(self.tmp.name)/'state.json')

    def test_map_identity_does_not_match_similar_module(self):
        result=parse_maps('1000-2000 r-xp 00000000 00:00 1 /path/libUE4.so\n'
                          '2000-3000 r--p 00001000 00:00 1 /path/libUE4.so\n'
                          '9000-a000 r-xp 00000000 00:00 2 /path/notlibUE4.so','libUE4.so')
        self.assertEqual(result['base'],0x1000)
        with self.assertRaises(TraceError):
            parse_maps('1000-2000 r-xp 00000000 00:00 1 /a/libUE4.so\n'
                       '3000-4000 r-xp 00000000 00:00 1 /b/libUE4.so','libUE4.so')

    def test_gnu_build_id_and_truncation(self):
        note=struct.pack('<III',4,20,3)+b'GNU\0'+bytes.fromhex('ab'*20)
        self.assertEqual(parse_build_id_notes(note),'ab'*20)
        self.assertEqual(parse_build_id_notes(note[:-1]),'')

    def test_root_binary_command_quoting(self):
        bridge=AdbBridge('adb')
        bridge.run=Mock(return_value=b'ok')
        bridge.shell('device','printf hello',root=True,binary=True)
        self.assertEqual(bridge.run.call_args.args[0][-1],'printf hello')
        bridge.shell('device','printf hello',root=True,binary=False)
        self.assertEqual(bridge.run.call_args.args[0][-1],"'printf hello'")

    def test_profile_mismatch_never_deploys(self):
        self.client.inspect=Mock(return_value={'profile_match':False})
        with self.assertRaisesRegex(TraceError,'偏移'):
            self.client.connect()
        self.client.adb.run.assert_not_called()

    def test_profile_preflight_validates_layout_and_normalizes_prologue(self):
        self.client.profile['process_event_prologue']='AA '*16
        self.client._validate_profile()
        self.assertEqual(self.client.profile['process_event_prologue'],'aa'*16)
        self.client.profile['layout']={}
        with self.assertRaisesRegex(TraceError,'布局'):
            self.client._validate_profile()

    def test_fragmented_stream_and_exact_command_response(self):
        a,b=socket.socketpair()
        a.settimeout(.1)
        self.client.sock=a
        self.client._reader=threading.Thread(target=self.client._receive,daemon=True)
        self.client._reader.start()
        self.addCleanup(self.client._shutdown_transport)
        self.addCleanup(b.close)
        def peer():
            request=json.loads(b.recv(8192))
            frame=(json.dumps({'type':'event','function':'Fixture.真实事件','call_id':1},ensure_ascii=False)+'\n'+
                   json.dumps({'type':'started','request_id':request['request_id'],'ok':True})+'\n').encode()
            split=frame.find('真实'.encode())+1
            b.sendall(frame[:split]); time.sleep(.02); b.sendall(frame[split:])
        t=threading.Thread(target=peer)
        t.start()
        reply=self.client.start(max_rate=100)
        t.join(2)
        self.assertEqual(reply['type'],'started')
        self.assertEqual(self.messages[0]['function'],'Fixture.真实事件')

    def test_disconnect_unblocks_waiter(self):
        a,b=socket.socketpair()
        a.settimeout(.1)
        self.client.sock=a
        self.client._reader=threading.Thread(target=self.client._receive,daemon=True)
        self.client._reader.start()
        def peer():
            b.recv(8192)
            b.close()
        t=threading.Thread(target=peer)
        t.start()
        started=time.monotonic()
        with self.assertRaises(TraceError):
            self.client.status()
        self.assertLess(time.monotonic()-started,2)
        t.join(2)
        self.client._shutdown_transport()

    def test_malformed_frame_stops_reader(self):
        a,b=socket.socketpair()
        a.settimeout(.1)
        self.client.sock=a
        t=threading.Thread(target=self.client._receive,daemon=True)
        t.start()
        b.sendall(b'[]\n')
        t.join(2)
        b.close()
        self.assertFalse(t.is_alive())
        self.assertTrue(self.client._closed.is_set())
        self.assertEqual(self.messages[-1]['type'],'disconnected')

    def test_corrupt_hello_is_error_not_injection_permission(self):
        server=socket.socket();server.bind(('127.0.0.1',0));server.listen(1)
        self.client.port=server.getsockname()[1];self.client.info={'pid':999}
        def peer():
            c,_=server.accept();c.sendall(b'{broken-json}\n');c.close();server.close()
        t=threading.Thread(target=peer);t.start()
        with self.assertRaisesRegex(TraceError,'握手格式'):
            self.client._try_socket()
        t.join(2)
        self.client.port=None

    def test_command_timeout_closes_socket_and_stops_remote_recording(self):
        a,b=socket.socketpair();a.settimeout(.1)
        self.client.sock=a
        self.client._reader=threading.Thread(target=self.client._receive,daemon=True)
        self.client._reader.start()
        observed=[]
        def peer():
            observed.append(json.loads(b.recv(8192)))
            observed.append(b.recv(8192));b.close()
        t=threading.Thread(target=peer);t.start()
        with self.assertRaisesRegex(TraceError,'未确认'):
            self.client._command('start',timeout=.1)
        t.join(2)
        self.assertEqual(observed[1],b'')
        self.assertIsNone(self.client.sock)
        self.assertTrue(self.client._closed.is_set())

    def _hello_socket(self, build, *, installed=True, protocol=1):
        sock=Mock()
        sock.recv.return_value=(json.dumps(dict(type='hello',protocol=protocol,pid=999,
                                               agent_build=build,hook_installed=installed))+'\n').encode()
        self.client.port=12345
        self.client.info={'pid':999}
        self.client._receive=Mock()
        return sock

    def test_compatible_resident_requires_hook_and_explicit_reuse(self):
        current='ad'*32; old='3b'*32
        (Path(self.tmp.name)/'native-manifest.json').write_text(json.dumps(
            {'protocol':1,'agent_build':current,'compatible_resident_builds':[old]}),encoding='utf-8')
        logs=[];self.client.on_log=logs.append
        sock=self._hello_socket(old)
        with patch('desktop.backend.socket.socket',return_value=sock):
            self.assertTrue(self.client._try_socket(reuse_resident=True))
        self.assertTrue(any('复用' in item and old in item for item in logs))
        self.client._shutdown_transport()
        for reuse,installed,protocol,build in [(False,True,1,old),(True,False,1,old),
                                               (True,True,2,old),(True,True,1,'ef'*32)]:
            with self.subTest(reuse=reuse,installed=installed,protocol=protocol,build=build):
                sock=self._hello_socket(build,installed=installed,protocol=protocol)
                with patch('desktop.backend.socket.socket',return_value=sock):
                    with self.assertRaises(TraceError):
                        self.client._try_socket(reuse_resident=reuse)
                sock.close.assert_called()
                self.client.port=None

    def _prepare_injection(self, failure=None, output='ok'):
        info=dict(package='example.fixture',profile_match=True,pid=999,starttime='123456',
                  base='0x1000',build_id='ab'*20,resident_observer=False)
        self.client.inspect=Mock(return_value=info)
        self.client._forward=Mock()
        self.client._try_socket=Mock(side_effect=[False,True])
        self.client._command=Mock(return_value={'type':'configured','ok':True})
        (Path(self.tmp.name)/'inject').write_bytes(b'TEST_ONLY')
        (Path(self.tmp.name)/'libue4trace.so').write_bytes(b'TEST_ONLY')
        def shell(serial, command, **kwargs):
            if command.endswith('--path-only'):
                if failure is not None:
                    raise failure
                return output
            return ''
        self.client.adb.shell.side_effect=shell
        return info

    def test_injection_exit_timeout_and_interrupt_persist_blocker(self):
        cases=[AdbCommandError('exit 11',returncode=11),AdbCommandError('exit 130',returncode=130),
               AdbCommandError('timeout',timed_out=True),KeyboardInterrupt()]
        for number,failure in enumerate(cases):
            with self.subTest(failure=type(failure).__name__,number=number):
                self.client._target_states=TargetStateStore(Path(self.tmp.name)/f'state-{number}.json')
                info=self._prepare_injection(failure)
                with self.assertRaises(type(failure)):
                    self.client.connect()
                rebuilt=PhoneTraceClient('adb','serial',self.tmp.name,Path(self.tmp.name)/'profile.json')
                rebuilt._target_states=TargetStateStore(self.client._target_states.path)
                rebuilt.inspect=Mock(return_value=info)
                rebuilt._forward=Mock()
                with self.assertRaisesRegex(TraceError,'状态不确定'):
                    rebuilt.connect()
                rebuilt._forward.assert_not_called()

    def test_uncertain_marker_in_success_exit_still_blocks(self):
        info=self._prepare_injection(output='TARGET_STATE_UNCERTAIN: target restored incompletely')
        with self.assertRaisesRegex(TraceError,'TARGET_STATE_UNCERTAIN'):
            self.client.connect()
        with self.assertRaisesRegex(TraceError,'状态不确定'):
            self.client._target_states.check('serial',info)
        self.client._command.assert_not_called()

    def test_success_clears_marker_and_new_starttime_is_allowed(self):
        info=self._prepare_injection()
        self.client.connect()
        self.client._target_states.check('serial',info)
        self.assertEqual(json.loads(self.client._target_states.path.read_text()),[])
        self.client._target_states.begin('serial',info)
        new_info=dict(info,starttime='999999')
        self.client._target_states.check('serial',new_info)
        self.client._target_states.begin('serial',new_info)
        self.client._target_states.clear('serial',new_info)
        self.assertEqual(json.loads(self.client._target_states.path.read_text()),[])

    def test_configure_failure_retains_injection_marker(self):
        info=self._prepare_injection()
        self.client._command.side_effect=TraceError('TEST_ONLY configure failure')
        with self.assertRaisesRegex(TraceError,'configure'):
            self.client.connect()
        with self.assertRaisesRegex(TraceError,'状态不确定'):
            self.client._target_states.check('serial',info)

    def test_corrupt_state_file_fails_closed(self):
        self.client._target_states.path.write_text('{invalid',encoding='utf-8')
        with self.assertRaisesRegex(TraceError,'状态记录'):
            self.client._target_states.check('serial',dict(package='example.fixture',pid=999,starttime='123'))

    def test_public_checkout_without_loader_never_deploys(self):
        self._prepare_injection()
        (Path(self.tmp.name)/'inject').unlink()
        with self.assertRaisesRegex(TraceError,'公开版不附带加载器'):
            self.client.connect()
        self.client.adb.run.assert_not_called()
        self.client.adb.shell.assert_not_called()
        self.client._command.assert_not_called()
        self.assertFalse(self.client._target_states.path.exists())

    def test_public_checkout_connects_to_loaded_observer_without_loader(self):
        info=dict(package='example.fixture',profile_match=True,pid=999,starttime='123456',
                  base='0x1000',build_id='ab'*20,resident_observer=True)
        self.client.inspect=Mock(return_value=info)
        self.client._forward=Mock()
        self.client._try_socket=Mock(return_value=True)
        self.client._command=Mock(return_value={'type':'configured','ok':True})
        result=self.client.connect()
        self.assertTrue(result['configured']['ok'])
        self.client._try_socket.assert_called_once_with(reuse_resident=True)
        self.client.adb.run.assert_not_called()
        self.client.adb.shell.assert_not_called()
        self.assertFalse((Path(self.tmp.name)/'inject').exists())

    def test_public_supplied_loader_still_requires_collector(self):
        self._prepare_injection()
        (Path(self.tmp.name)/'libue4trace.so').unlink()
        with self.assertRaisesRegex(TraceError,'缺少 libue4trace.so'):
            self.client.connect()
        self.client.adb.shell.assert_not_called()

    def test_public_preferences_ignore_stale_paths_and_use_separate_settings(self):
        from desktop.ui import saved_file_or_default, SETTINGS_APPLICATION, default_profile_path
        existing=Path(self.tmp.name)/'profile.json'
        fallback=str(existing)
        for saved in ('', '   ', None, str(existing.parent/'missing.json'), str(existing.parent)):
            with self.subTest(saved=saved):
                self.assertEqual(saved_file_or_default(saved,fallback),fallback)
        self.assertEqual(saved_file_or_default(str(existing), 'unused'),str(existing))
        self.assertNotEqual(SETTINGS_APPLICATION,'EventObserver')
        assets=Path(self.tmp.name)/'assets'
        self.assertEqual(Path(default_profile_path(assets)).parent.name,'profiles')
        assets.mkdir()
        bundled=assets/'pubgmhd-1.39.13-arm64.json'
        bundled.write_text('{}',encoding='utf-8')
        self.assertEqual(default_profile_path(assets),str(bundled))

    def test_missing_or_invalid_manifest_fails_before_any_device_operation(self):
        manifest=Path(self.tmp.name)/'native-manifest.json'
        invalid=[None,'{broken','[]',json.dumps({'protocol':1,'agent_build':'short'}),
                 json.dumps({'protocol':2,'agent_build':'ad'*32}),
                 json.dumps({'protocol':1,'agent_build':'ad'*32,'compatible_resident_builds':'ef'*32})]
        self.client.inspect=Mock()
        self.client._forward=Mock()
        for content in invalid:
            with self.subTest(content=content):
                if content is None:
                    manifest.unlink(missing_ok=True)
                else:
                    manifest.write_text(content,encoding='utf-8')
                with self.assertRaisesRegex(TraceError,'native-manifest'):
                    self.client.connect()
                self.client.inspect.assert_not_called()
                self.client._forward.assert_not_called()
                self.client.adb.run.assert_not_called()
                self.client.adb.shell.assert_not_called()

    def test_real_hello_rejects_unknown_collector_build(self):
        server=socket.socket();server.bind(('127.0.0.1',0));server.listen(1)
        self.client.port=server.getsockname()[1]
        self.client.info={'pid':999}
        peer_closed=[]
        def peer():
            connection,_=server.accept()
            connection.settimeout(2)
            connection.sendall((json.dumps({'type':'hello','protocol':1,'pid':999,
                                           'agent_build':'ef'*32,'hook_installed':True})+'\n').encode())
            peer_closed.append(connection.recv(1))
            connection.close();server.close()
        thread=threading.Thread(target=peer);thread.start()
        try:
            with self.assertRaisesRegex(TraceError,'未允许复用'):
                self.client._try_socket(reuse_resident=True)
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(peer_closed,[b''])
            self.assertIsNone(self.client.sock)
            self.client.adb.shell.assert_not_called()
        finally:
            self.client.port=None

if __name__=='__main__':
    unittest.main()
