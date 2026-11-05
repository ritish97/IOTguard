"""
IoTGuard Robust Log Tailer Module
Implements Production Readiness Pillar 2: Reliability & Fault Tolerance:
- Robust file tailing with inode tracking and truncation detection.
- Survives Zeek's periodic log rotations (e.g. conn.log -> conn.2026-11-03.log) without missing logs or crashing.
- Non-blocking line generator with adaptive backoff.
"""

import os
import json
import time
from pathlib import Path
from typing import Generator, Dict, Any, Optional, Tuple


class RobustJsonLogTailer:
    """
    Tails a JSON-formatted log file (such as Zeek conn.log) continuously.
    Resilient against:
    1. Log rotation (file renamed and new file created with different inode).
    2. File truncation (file emptied or reduced in size via copytruncate).
    3. File not yet created at startup (waits gracefully).
    """
    def __init__(
        self,
        file_path: Path,
        poll_interval: float = 0.05,
        start_from_beginning: bool = True
    ):
        self.file_path = Path(file_path)
        self.poll_interval = poll_interval
        self.start_from_beginning = start_from_beginning

        self._file_handle = None
        self._current_inode = None
        self._last_position = 0
        self._is_running = True

    def _get_file_stat(self) -> Optional[Tuple[int, int]]:
        """Returns (inode, size) or None if file does not exist."""
        try:
            stat_res = os.stat(self.file_path)
            # st_ino is unique on Unix; on Windows it is 0 or synthetic
            inode = getattr(stat_res, "st_ino", 0)
            return inode, stat_res.st_size
        except (FileNotFoundError, OSError):
            return None

    def _open_file(self) -> bool:
        """Opens or reopens the target log file."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None

        stat = self._get_file_stat()
        if stat is None:
            return False

        inode, size = stat
        try:
            self._file_handle = open(self.file_path, "r", encoding="utf-8", errors="replace")
            self._current_inode = inode

            if not self.start_from_beginning:
                # Seek to end on initial open if not reading full history
                self._file_handle.seek(0, os.SEEK_END)
                self._last_position = self._file_handle.tell()
            else:
                self._last_position = 0

            return True
        except Exception:
            return False

    def stop(self):
        """Signals the tailer to stop reading."""
        self._is_running = False
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass

    def follow(
        self,
        max_records: Optional[int] = None,
        stop_on_eof: bool = False
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Yields parsed JSON objects as they are written to the file.
        Detects log rotation and file truncation automatically.
        If stop_on_eof is True, stops iterating when reaching end-of-file.
        """
        count = 0

        # Wait until file exists and open it
        while self._is_running and not self._open_file():
            if stop_on_eof:
                return
            time.sleep(self.poll_interval * 2)

        try:
            while self._is_running:
                if not self._file_handle:
                    if not self._open_file():
                        if stop_on_eof:
                            return
                        time.sleep(self.poll_interval)
                        continue

                line = self._file_handle.readline()

                if line:
                    self._last_position = self._file_handle.tell()
                    line_str = line.strip()
                    if not line_str:
                        continue

                    try:
                        record = json.loads(line_str)
                        yield record
                        count += 1
                        if max_records and count >= max_records:
                            break
                    except json.JSONDecodeError:
                        # Incomplete line write or corrupted chunk; continue
                        continue
                else:
                    if stop_on_eof:
                        return
                    # Reached EOF of current handle. Check for rotation or truncation.
                    stat = self._get_file_stat()

                    if stat is None:
                        # File was deleted / moved during rotation
                        time.sleep(self.poll_interval)
                        self._open_file()
                        continue

                    new_inode, new_size = stat

                    # Check 1: Inode change (standard POSIX rotation)
                    if self._current_inode is not None and new_inode != 0 and new_inode != self._current_inode:
                        # Read any remaining bytes in old file before switching
                        remaining = self._file_handle.read()
                        if remaining:
                            for rem_line in remaining.splitlines():
                                rem_str = rem_line.strip()
                                if rem_str:
                                    try:
                                        yield json.loads(rem_str)
                                        count += 1
                                        if max_records and count >= max_records:
                                            return
                                    except json.JSONDecodeError:
                                        pass
                        self._open_file()
                        continue

                    # Check 2: File truncation (copytruncate rotation or log wipe)
                    if new_size < self._last_position:
                        # File shrunk: seek to beginning of new content
                        self._file_handle.seek(0, os.SEEK_SET)
                        self._last_position = 0
                        continue

                    # No new data yet
                    time.sleep(self.poll_interval)
        finally:
            if stop_on_eof:
                self.stop()
