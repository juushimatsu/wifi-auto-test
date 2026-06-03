from abc import ABC, abstractmethod


class IDependencyInstaller(ABC):
    @abstractmethod
    def install_all(self) -> bool:
        pass

    @abstractmethod
    def check_binaries(self) -> dict[str, bool]:
        pass
