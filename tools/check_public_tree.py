"""Check tracked publication inputs without printing any matched secret."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BLOCKED_SUFFIXES = {'.so', '.a', '.dll', '.exe', '.apk', '.aab', '.bin', '.dmp', '.zip', '.jsonl', '.ndjson'}
BLOCKED_PARTS = {'.venv', '__pycache__', 'validation', 'packaging-build', '_deps', 'assets'}
PATTERNS = {
    'access credential': re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})'),
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'local user path': re.compile(r'[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+|[A-Za-z]:[\\/]+myprojects[\\/]'),
    'runtime profile evidence': re.compile(r'"(?:sample_pid|sample_load_bias|sample_process_event_address)"\s*:'),
}

def publication_files():
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, capture_output=True)
    if result.returncode == 0 and result.stdout:
        return [ROOT / item.decode('utf-8') for item in result.stdout.split(b'\0') if item]
    return [p for p in ROOT.rglob('*') if p.is_file() and '.git' not in p.relative_to(ROOT).parts
            and not any(part in BLOCKED_PARTS | {'build', 'dist'} for part in p.relative_to(ROOT).parts)]

def main():
    failures = []
    files = publication_files()
    for path in files:
        relative = path.relative_to(ROOT)
        if path.suffix.lower() in BLOCKED_SUFFIXES or any(part in BLOCKED_PARTS for part in relative.parts):
            failures.append((str(relative), 'excluded artifact type'))
            continue
        try:
            content = path.read_text(encoding='utf-8-sig')
        except (UnicodeError, OSError):
            failures.append((str(relative), 'unexpected non-text or unreadable file'))
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                failures.append((str(relative), label))
    for relative, label in failures:
        print(f'FAIL {relative}: {label} (value withheld)')
    print(f'Checked {len(files)} publication files; {len(failures)} findings.')
    return bool(failures)

if __name__ == '__main__':
    sys.exit(main())
