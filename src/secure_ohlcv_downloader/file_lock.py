from __future__ import annotations
"""Cross-platform file locking utilities using the filelock library."""

import os
import threading
from contextlib import contextmanager
from typing import Dict

from filelock import FileLock, Timeout

from .exceptions import FileLockTimeoutError


class CrossPlatformFileLockManager:
    """Manage file locks in a cross-platform manner."""

    def __init__(self) -> None:
        self._locks: Dict[str, FileLock] = {}
        self._mutex = threading.RLock()

    @contextmanager
    def secure_file_lock(self, file_path: str, timeout: float = 10.0):
        """Context manager that acquires an exclusive lock on *file_path*.

        Attack scenario: concurrent processes writing to the same file could
        corrupt data or expose race conditions. A per-file lock combined with
        a timeout prevents indefinite blocking and signals a
        :class:`FileLockTimeoutError` when contention occurs.
        """
        lock_path = f"{file_path}.lock"
        with self._mutex:
            file_lock = self._locks.setdefault(lock_path, FileLock(lock_path))
        try:
            file_lock.acquire(timeout=timeout)
            with open(file_path, "a+b") as handle:
                yield handle
        except Timeout as exc:
            raise FileLockTimeoutError(f"Failed to acquire file lock for {file_path}") from exc
        finally:
            if file_lock.is_locked:
                file_lock.release()
            if not file_lock.is_locked and os.path.exists(lock_path):
                os.remove(lock_path)

    def is_file_locked(self, file_path: str) -> bool:
        """Return True if *file_path* is currently locked."""
        lock_path = f"{file_path}.lock"
        with self._mutex:
            lock = self._locks.get(lock_path, FileLock(lock_path))
        return lock.is_locked

    def cleanup_stale_locks(self) -> None:
        """Remove lock files for which no process holds the lock.

        Mitigation strategy: cleans up orphaned lock files that might remain
        after crashes, preventing future deadlocks on startup.
        """
        with self._mutex:
            stale = [path for path, lock in self._locks.items() if not lock.is_locked]
            for path in stale:
                if os.path.exists(path):
                    os.remove(path)
                del self._locks[path]
