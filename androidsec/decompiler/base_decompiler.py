"""
Base Decompiler - Tüm decompiler'ların türetileceği temel sınıf
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class BaseDecompiler(ABC):
    """Tüm decompiler implementasyonları bu sınıftan türetilir."""

    @abstractmethod
    def decompile(self, apk_path: str, output_dir: str) -> bool:
        """
        APK'yı dekompile et.

        Args:
            apk_path: APK dosyası yolu
            output_dir: Çıktı klasörü yolu

        Returns:
            True başarılıysa, False değilse
        """

    def is_available(self) -> bool:
        """Araç sisteme kurulu mu kontrol et."""
        return False

    def _ensure_output_dir(self, output_dir: str) -> Path:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        return out
