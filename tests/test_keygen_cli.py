import os
import stat
import subprocess
import sys
from pathlib import Path


def test_keygen_writes_0600_key(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "knok.keygen", "--name", "carl", "--hub", "bridge.example",
         "--dir", str(tmp_path)],
        capture_output=True, text=True, cwd=root, env={**os.environ, "PYTHONPATH": str(root / "src")},
    )
    assert result.returncode == 0, result.stderr
    assert "carl@bridge.example" in result.stdout
    key = tmp_path / "carl.key"
    assert key.exists()
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_keygen_refuses_second_run(tmp_path):
    root = Path(__file__).resolve().parents[1]
    cmd = [sys.executable, "-m", "knok.keygen", "--name", "carl", "--hub", "bridge.example",
           "--dir", str(tmp_path)]
    env = {**os.environ, "PYTHONPATH": str(root / "src")}
    subprocess.run(cmd, capture_output=True, text=True, cwd=root, env=env)
    second = subprocess.run(cmd, capture_output=True, text=True, cwd=root, env=env)
    assert second.returncode == 1
    assert "refusing to overwrite" in second.stderr
