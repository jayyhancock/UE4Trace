"""Exercise a forwarded ARM64 fixture observer. Does not deploy or touch ADB.

Usage: py -3.13 fixture_protocol.py <local-port> <downloaded-fixture-profile.json>
The fixture must be running with the freshly built collector loaded.
"""
import argparse
import copy
import json
import socket
import time


class Client:
    def __init__(self, port):
        self.socket = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.buffer = b''
        self.request = 0
        self.hello = self.next(5)

    def next(self, timeout):
        until = time.monotonic() + timeout
        while b'\n' not in self.buffer:
            self.socket.settimeout(max(0.001, until - time.monotonic()))
            data = self.socket.recv(65536)
            if not data:
                raise RuntimeError('Observer disconnected')
            self.buffer += data
        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line)

    def command(self, command, **fields):
        self.request += 1
        data = dict(cmd=command, request_id=self.request, **fields)
        self.socket.sendall((json.dumps(data) + '\n').encode())
        until = time.monotonic() + 8
        while time.monotonic() < until:
            message = self.next(until - time.monotonic())
            if message.get('request_id') == self.request:
                return message
        raise RuntimeError('Missing command response')

    def collect(self, duration):
        until = time.monotonic() + duration
        messages = []
        while time.monotonic() < until:
            try:
                messages.append(self.next(until - time.monotonic()))
            except socket.timeout:
                break
        return messages


def run(port, profile):
    c = Client(port)
    assert c.hello['type'] == 'hello'
    assert not c.hello['recording']
    fresh = not c.hello['hook_installed']
    c.socket.sendall(b'[]\n')
    while True:
        malformed = c.next(3)
        if malformed['type'] == 'error':
            break
    if fresh:
        bad = copy.deepcopy(profile)
        bad['build_id'] = '00' * 20
        assert c.command('configure', profile=bad)['type'] == 'error'
        bad = copy.deepcopy(profile)
        bad['process_event_prologue'] = '00' * 16
        assert c.command('configure', profile=bad)['type'] == 'error'
        assert not c.command('status')['hook_installed']
    assert c.command('configure', profile=profile)['ok']
    assert c.command('configure', profile=profile)['ok'], 'Repeat configure must be idempotent'
    changed = copy.deepcopy(profile)
    changed['process_event_prologue'] = '00' * 16
    assert c.command('configure', profile=changed)['type'] == 'error'
    assert c.command('status')['hook_installed'], 'Rejected profile must preserve installed hook'
    assert c.command('start', max_rate=0)['type'] == 'error'
    assert c.command('start', max_rate=1000)['ok']
    events = [m for m in c.collect(1.5) if m['type'] == 'event']
    assert len(events) >= 20, len(events)
    ids = {e['call_id']: e for e in events}
    assert len(ids) == len(events)
    roots = [e for e in events if e['depth'] == 0 and 'RootEvent' in e['function']]
    nested = [e for e in events if e['depth'] == 1 and 'NestedEvent' in e['function']]
    assert roots and nested
    linked = [e for e in nested if e['parent_id'] in ids and 'RootEvent' in ids[e['parent_id']]['function']]
    assert len(linked) >= 5, len(linked)
    assert all('TestObject' in e['object'] for e in events)
    assert c.command('pause')['type'] == 'paused'
    assert not [m for m in c.collect(.3) if m['type'] == 'event']
    assert c.command('start', include='RootEvent', max_rate=1000)['ok']
    filtered = [m for m in c.collect(.5) if m['type'] == 'event']
    assert filtered and all('RootEvent' in e['function'] for e in filtered)
    stopped = c.command('stop')
    assert stopped['hook_state'] == 'pass-through'
    assert not stopped['recording']
    c.socket.close()
    time.sleep(.1)
    d = Client(port)
    assert d.hello['hook_installed'] and not d.hello['recording']
    d.socket.close()
    return dict(passed=True, fresh_hook_install=fresh, completed_events=len(events), nested_parent_links=len(linked), filtered_events=len(filtered), final_status=stopped)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int)
    parser.add_argument('profile')
    args = parser.parse_args()
    with open(args.profile, encoding='utf-8') as f:
        profile = json.load(f)
    print(json.dumps(run(args.port, profile), indent=2, ensure_ascii=False))
