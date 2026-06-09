"""
APK Extractor - En uygun decompiler'ı seçip dekompilasyon yapar
"""

from pathlib import Path
from typing import Optional

from androidsec.decompiler.jadx_wrapper import JADXWrapper
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class APKExtractor:
    """
    APK'yı dekompile etmek için facade sınıfı.

    JADX mevcut ise kullanır, değilse hata loglar.

    Kullanım:
        extractor = APKExtractor()
        out_dir = extractor.extract("app.apk", "output/decompiled/app")
    """

    def __init__(self, timeout: int = 300):
        self._jadx = JADXWrapper(timeout=timeout)

    def extract(self, apk_path: str, output_dir: str) -> Optional[str]:
        """
        APK'yı dekompile et.

        Args:
            apk_path:   APK dosyası yolu
            output_dir: Çıktı klasörü

        Returns:
            output_dir (başarılıysa), None (başarısızsa)
        """
        out = Path(output_dir)

        # Zaten dekompile edilmişse tekrar yapma
        if (out / "AndroidManifest.xml").exists():
            logger.info(f"Zaten dekompile edilmiş, atlanıyor: {output_dir}")
            return output_dir

        if self._jadx.is_available():
            logger.info(f"JADX ile dekompile ediliyor: {apk_path} → {output_dir}")
            success = self._jadx.decompile(apk_path, output_dir)
            if success:
                return output_dir
            logger.error("JADX dekompilasyonu başarısız.")
            return None

        logger.error("Kullanılabilir decompiler bulunamadı (JADX yüklü değil).")
        return None

    def is_any_available(self) -> bool:
        return self._jadx.is_available()
