from abc import ABC, abstractmethod
from typing import Any, Optional


class IConfigStore(ABC):
    @abstractmethod
    def get(self, key: str, default: Any = None) -> Any:
        """Получить значение по ключу."""
        pass

    @abstractmethod
    def set(self, key: str, value: Any) -> None:
        """Установить значение по ключу."""
        pass

    @abstractmethod
    def save(self) -> None:
        """Сохранить конфигурацию на диск."""
        pass
