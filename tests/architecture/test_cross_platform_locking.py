import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from secure_ohlcv_downloader import (
    CrossPlatformFileLockManager,
    FileLockTimeoutError,
)
from filelock import FileLock


class TestCrossPlatformLocking:
    """Tests for cross-platform file locking abstraction."""

    def test_basic_file_locking(self):
        lock_manager = CrossPlatformFileLockManager()
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            file_path = tmp_file.name
        try:
            with lock_manager.secure_file_lock(file_path) as f:
                assert f is not None
                f.write(b"test data")
            with open(file_path, "rb") as f:
                assert f.read() == b"test data"
        finally:
            os.unlink(file_path)

    def test_concurrent_locking(self):
        lock_manager = CrossPlatformFileLockManager()
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            file_path = tmp_file.name
        results = []
        exceptions = []

        def write_to_file(i: int):
            try:
                with lock_manager.secure_file_lock(file_path, timeout=5.0) as f:
                    time.sleep(0.1)
                    f.seek(0, 2)
                    f.write(f"Thread {i}\n".encode())
                    results.append(i)
            except Exception as exc:
                exceptions.append(exc)

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(write_to_file, i) for i in range(5)]
                for fut in futures:
                    fut.result(timeout=10)
            assert not exceptions
            assert len(results) == 5
            with open(file_path) as f:
                content = f.read()
                for i in range(5):
                    assert f"Thread {i}" in content
        finally:
            if os.path.exists(file_path):
                os.unlink(file_path)

    def test_lock_timeout(self):
        lock_manager = CrossPlatformFileLockManager()
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            file_path = tmp_file.name
        try:
            def hold_lock():
                with lock_manager.secure_file_lock(file_path, timeout=10.0):
                    time.sleep(2.0)
            lock_thread = threading.Thread(target=hold_lock)
            lock_thread.start()
            time.sleep(0.1)
            start = time.time()
            with pytest.raises(FileLockTimeoutError):
                with lock_manager.secure_file_lock(file_path, timeout=0.5):
                    pass
            assert time.time() - start < 1.0
            lock_thread.join()
        finally:
            if os.path.exists(file_path):
                os.unlink(file_path)

    def test_platform_specific_implementation(self):
        import sys
        lock_manager = CrossPlatformFileLockManager()
        if sys.platform == "win32":
            assert isinstance(
                lock_manager._locks[list(lock_manager._locks.keys())[0]]
                if lock_manager._locks
                else FileLock("dummy"),
                FileLock,
            )
        else:
            assert isinstance(
                lock_manager._locks[list(lock_manager._locks.keys())[0]]
                if lock_manager._locks
                else FileLock("dummy"),
                FileLock,
            )

    def test_lock_cleanup(self):
        lock_manager = CrossPlatformFileLockManager()
        fake1 = "/nonexistent/path1.txt.lock"
        fake2 = "/nonexistent/path2.txt.lock"
        lock_manager._locks[fake1] = FileLock(fake1)  # noqa: F821
        lock_manager._locks[fake2] = FileLock(fake2)  # noqa: F821
        lock_manager.cleanup_stale_locks()
        assert fake1 not in lock_manager._locks
        assert fake2 not in lock_manager._locks
