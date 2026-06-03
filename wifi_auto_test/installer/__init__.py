from .interfaces import IDependencyInstaller
from .apt_installer import AptInstaller
from .pacman_installer import PacmanInstaller

__all__ = ["IDependencyInstaller", "AptInstaller", "PacmanInstaller"]
