"""One interactive application per data directory (OS releases on crash)."""
import os
from pathlib import Path


class LocalAppLock:
    def __init__(self, home):
        path = Path(home) / 'data' / '.application.lock'
        path.parent.mkdir(parents=True, exist_ok=True)
        self.file = path.open('a+b')
        try:
            self.file.seek(0)
            if os.name == 'nt':
                import msvcrt
                if not path.stat().st_size:
                    self.file.write(b'0'); self.file.flush(); self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise RuntimeError('此数据目录已有程序运行，请先关闭它；不要同时启动两个采集器') from None

    def close(self):
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
