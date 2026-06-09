"""
androidsec/dynamic_analysis/analyzer.py

Dynamic analysis'in ana koordinatörü.
Cihaz yönetimi, log toplama, network ve storage analizlerini orkestra eder.
"""

import logging
import time

from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper
from androidsec.dynamic_analysis.device.manager import DeviceManager
from androidsec.dynamic_analysis.collectors.logcat import LogcatCollector
from androidsec.dynamic_analysis.collectors.network import NetworkCollector
from androidsec.dynamic_analysis.collectors.storage import StorageCollector

logger = logging.getLogger(__name__)


class DynamicAnalyzer:
    """
    Dinamik analiz orkestratörü.

    Cihaz üzerinde APK çalıştırır, logları toplar ve
    network + storage güvenlik analizlerini gerçekleştirir.

    Kullanım:
        adb = ADBWrapper()
        analyzer = DynamicAnalyzer(adb)
        result = analyzer.analyze("app.apk", "com.example.app")
    """

    def __init__(self, adb, log_duration_seconds=15):
        self.adb = adb
        self.log_duration_seconds = log_duration_seconds

        self.device_manager = DeviceManager(adb)
        self.network_collector = NetworkCollector()
        self.storage_collector = StorageCollector()

    def analyze(self, apk_path, package_name):
        """
        APK'yı cihaza kurar, çalıştırır ve güvenlik analizlerini yapar.

        Args:
            apk_path: APK dosya yolu
            package_name: Uygulamanın paket adı

        Returns:
            dict: Analiz sonuçları (findings, summary, logs)
        """
        logger.info("=== Dynamic analiz başlıyor: %s ===", package_name)

        # 1. Cihaz hazırla
        logger.info("Cihaz hazırlanıyor...")
        self.device_manager.prepare_device()

        # 2. APK kur
        logger.info("APK kuruluyor...")
        self.device_manager.install_app(apk_path)

        # 3. Log topla (Pasif Dinamik Analiz)
        logger.info("Log toplanıyor (Pasif Dinamik Analiz)...")

        logcat_collector = LogcatCollector(self.adb)

        logs = logcat_collector.collect(
            package_name=package_name,
            duration_seconds=self.log_duration_seconds
        )

        # 4. Network analizi
        logger.info("Network analizi yapılıyor...")
        network_findings = self.network_collector.analyze(logs)

        # 5. Storage analizi
        logger.info("Storage analizi yapılıyor...")
        storage_findings = self.storage_collector.analyze(logs)

        # 6. Frida WebView hook analizi (Frida kuruluysa)
        frida_findings = []
        try:
            from androidsec.dynamic_analysis.frida.frida_manager import FridaManager
            logger.info("Frida WebView hook analizi başlatılıyor...")
            frida = FridaManager(self.adb)
            frida.attach(package_name)
            frida.run_script("webview_hooks")
            frida.run_script("network_hooks")
            time.sleep(self.log_duration_seconds)
            frida_findings = frida.get_findings()
            frida.detach()
            logger.info("Frida analizi tamamlandı: %d bulgu", len(frida_findings))
        except Exception as e:
            logger.info("Frida analizi atlandı: %s", str(e))

        # 7. Hepsini birleştir
        all_findings = network_findings + storage_findings + frida_findings

        # 7. Özet çıkar
        summary = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        summary["total"] = len(all_findings)

        for f in all_findings:
            severity = f.get("severity", "").upper()

            if severity == "CRITICAL":
                summary["critical"] += 1
            elif severity == "HIGH":
                summary["high"] += 1
            elif severity == "MEDIUM":
                summary["medium"] += 1
            elif severity == "LOW":
                summary["low"] += 1

        logger.info("=== Analiz tamamlandı ===")
        logger.info("Toplam bulgu: %d", summary["total"])

        return {
            "package": package_name,
            "summary": summary,
            "findings": all_findings,
            "network_findings": network_findings,
            "storage_findings": storage_findings,
            "logs": logs
        }
