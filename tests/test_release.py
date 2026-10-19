"""Desktop release boundaries and retained safety fixes; no capture or paid model."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.runtime'))

from traffic_agent.local_lock import LocalAppLock
from traffic_agent.replay import Replay


class ReleaseTests(unittest.TestCase):
    def test_cli_is_desktop_only_and_rejects_web_before_opening_database(self):
        help_result = subprocess.run([sys.executable, '-X', 'utf8', str(ROOT / 'app.py'), '--help'],
                                     capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn('Traffic Monitoring', help_result.stdout)
        self.assertIn('--replay', help_result.stdout)
        self.assertNotIn('--web', help_result.stdout)
        result = subprocess.run([sys.executable, '-X', 'utf8', str(ROOT / 'app.py'), '--web'],
                                capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertIn('unrecognized arguments', result.stderr)

    def test_data_directory_lock_blocks_another_process_then_releases(self):
        script = ('import sys; from traffic_agent.local_lock import LocalAppLock\n'
                  'try:\n with LocalAppLock(sys.argv[1]): pass\n'
                  'except RuntimeError:\n sys.exit(7)\n')
        with tempfile.TemporaryDirectory() as home:
            command = [sys.executable, '-c', script, home]
            with LocalAppLock(home):
                result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 7, result.stderr)
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_pcap_does_not_leave_a_file_handle_open(self):
        from scapy.error import Scapy_Exception
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'invalid.pcap'
            path.write_bytes(b'not a capture file')
            with self.assertRaises(Scapy_Exception):
                Replay(path)
            # Windows refuses deletion when the rejected reader leaked its handle.
            path.unlink()
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
