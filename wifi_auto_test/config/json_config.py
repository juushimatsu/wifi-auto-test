import json
import os
from pathlib import Path
from typing import Any

from .interfaces import IConfigStore
from .default_settings import DEFAULT_SETTINGS


class JsonConfigStore(IConfigStore):
    def __init__(self, filepath: str = "settings.json"):
        self._filepath = Path(filepath)
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        if self._filepath.exists():
            try:
                with open(self._filepath, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._data = dict(DEFAULT_SETTINGS)
        else:
            self._data = dict(DEFAULT_SETTINGS)
            self.save()

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._data:
            return self._data[key]
        if key in DEFAULT_SETTINGS:
            return DEFAULT_SETTINGS[key]
        return default

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def save(self) -> None:
        os.makedirs(self._filepath.parent, exist_ok=True)
        with open(self._filepath, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)
