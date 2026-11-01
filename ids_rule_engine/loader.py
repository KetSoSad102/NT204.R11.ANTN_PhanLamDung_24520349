from __future__ import annotations

from pathlib import Path
from typing import Iterable


class RuleLoader:
    def __init__(
        self,
        disabled_rules: set[int | str] | None = None,
        disabled_files: set[str] | None = None,
    ):
        self.disabled_rules: set[int | str] = set(disabled_rules or [])
        self.disabled_files: set[str] = set(disabled_files or [])
        self.warnings: list[str] = []

    def is_file_enabled(self, file_path: str | Path) -> bool:
        p = Path(file_path)
        return p.name not in self.disabled_files and str(p) not in self.disabled_files

    def load_from_lines(self, lines: Iterable[str], file_path: str | None = None) -> list[tuple[int, str]]:
        valid_lines: list[tuple[int, str]] = []
        for line_no, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            valid_lines.append((line_no, line))
        return valid_lines

    def load_from_string(self, text: str, file_path: str | None = None) -> list[tuple[int, str]]:
        return self.load_from_lines(text.splitlines(), file_path=file_path)

    def load_file(self, file_path: str | Path) -> list[tuple[int, str]]:
        path = Path(file_path)
        if not path.exists():
            self.warnings.append(f"File not found: {path}")
            return []
        if not self.is_file_enabled(path):
            return []
        try:
            with path.open("r", encoding="utf-8") as f:
                return self.load_from_lines(f, file_path=str(path))
        except Exception as exc:
            self.warnings.append(f"Error reading {path}: {exc}")
            return []

    def load_rule_strings(self, file_path: str | Path) -> list[str]:
        return [rule for _, rule in self.load_file(file_path)]

    def load_files(self, paths: list[str | Path]) -> list[tuple[str, int, str]]:
        results: list[tuple[str, int, str]] = []
        for path in paths:
            lines = self.load_file(path)
            for line_no, line in lines:
                results.append((str(path), line_no, line))
        return results

    def load_directory(self, dir_path: str | Path, pattern: str = "*.rules") -> list[tuple[str, int, str]]:
        path = Path(dir_path)
        if not path.is_dir():
            self.warnings.append(f"Directory not found: {path}")
            return []
        files = sorted(path.glob(pattern))
        return self.load_files(files)

