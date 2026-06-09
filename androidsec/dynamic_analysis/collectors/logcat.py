"""
androidsec/dynamic_analysis/collectors/logcat.py

Uygulama çalışırken logcat çıktısını toplayan collector.
Sadece log toplar, analiz yapmaz.
"""

import logging
import time

from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper
from androidsec.dynamic_analysis.device.manager import DeviceManager

logger = logging.getLogger(__name__)


class LogcatCollector:
    def __init__(self, adb: ADBWrapper, device_manager: DeviceManager = None):
        self.adb = adb
        self.device_manager = device_manager

    def collect(self, package_name: str, duration_seconds: int = 10, clear_first: bool = True) -> str:
        """
        Uygulamayı başlatır, biraz bekler ve logcat çıktısını döndürür.
        """

        logger.info("Logcat toplama başlatılıyor: %s", package_name)

        if clear_first:
            self.adb.clear_logcat()

        if self.device_manager is not None:
            self.device_manager.launch_app(package_name)
        else:
            self.adb.launch_app(package_name)

        logger.info("%d saniye boyunca log toplanıyor...", duration_seconds)
        time.sleep(duration_seconds)

        # Sadece bu paketin loglarını al — diğer uygulamaların logları karışmasın
        logs = self.adb.get_logcat_dump(package_name=package_name)

        logger.info("Logcat toplama tamamlandı.")
        return logs

    def collect_to_file(
        self,
        package_name: str,
        output_path: str,
        duration_seconds: int = 10,
        clear_first: bool = True,
    ) -> str:
        """
        Logcat çıktısını dosyaya kaydeder.
        """

        logger.info("Logcat dosyaya kaydedilecek: %s", output_path)

        logs = self.collect(
            package_name=package_name,
            duration_seconds=duration_seconds,
            clear_first=clear_first,
        )

        with open(output_path, "w", encoding="utf-8") as file:
            file.write(logs)

        logger.info("Loglar dosyaya yazıldı.")
        return output_path
