"""
JADX Wrapper - JADX ile APK dekompilasyonu
"""

import shutil
import subprocess
from pathlib import Path

from androidsec.decompiler.base_decompiler import BaseDecompiler
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)

# JADX binary arama sırası
_JADX_CANDIDATES = [
    "jadx",                                      # PATH'te
    "/opt/homebrew/bin/jadx",                   # macOS Homebrew (Apple Silicon)
    "/usr/local/bin/jadx",                      # macOS Homebrew (Intel)
    "/usr/bin/jadx",                            # Linux
]

# Proje içindeki JADX
_PROJECT_JADX = Path(__file__).parent.parent.parent / "tools" / "jadx" / "bin" / "jadx"


def _find_jadx() -> str | None:
    """Sistemde kullanılabilir JADX binary'sini bul."""
    if _PROJECT_JADX.exists():
        return str(_PROJECT_JADX)
    for candidate in _JADX_CANDIDATES:
        if shutil.which(candidate):
            return candidate
    return None


class JADXWrapper(BaseDecompiler):
    """JADX kullanarak APK'yı Java kaynak koduna çevirir."""

    def __init__(self, timeout: int = 300):
        self._jadx_bin = _find_jadx()
        self._timeout = timeout

    def is_available(self) -> bool:
        return self._jadx_bin is not None

    def decompile(self, apk_path: str, output_dir: str) -> bool:
        """
        APK'yı JADX ile dekompile et.

        Üretir: output_dir/AndroidManifest.xml + output_dir/sources/...
        """
        if not self._jadx_bin:
            logger.error("JADX bulunamadı. 'brew install jadx' veya PATH'e ekleyin.")
            return False

        out = self._ensure_output_dir(output_dir)

        cmd = [
            self._jadx_bin,
            "--output-dir", str(out),
            "--export-gradle",          # kaynak yapısını koru
            "--no-debug-info",          # temiz çıktı
            "--show-bad-code",          # hatalı kod olsa bile devam et
            apk_path,
        ]

        logger.info(f"JADX çalıştırılıyor: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            if result.returncode == 0:
                logger.info(f"JADX başarıyla tamamlandı: {output_dir}")
                return True
            else:
                # JADX kısmen başarılı olsa da çıktı üretir; AndroidManifest.xml
                # varsa yeterli sayarız.
                manifest = out / "AndroidManifest.xml"
                if manifest.exists():
                    logger.warning(
                        f"JADX uyarılarla tamamlandı (kod={result.returncode}), "
                        "AndroidManifest.xml mevcut — devam ediliyor."
                    )
                    return True
                logger.error(f"JADX başarısız (kod={result.returncode}):\n{result.stderr[:500]}")
                return False
        except subprocess.TimeoutExpired:
            logger.error(f"JADX zaman aşımı ({self._timeout}s): {apk_path}")
            return False
        except Exception as e:
            logger.error(f"JADX çalıştırma hatası: {e}")
            return False
