"""
androidsec/dynamic_analysis/device/manager.py

Cihaz yönetimi - cihaz hazırlama, uygulama kurma ve başlatma.
"""

from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper
import logging

logger = logging.getLogger(__name__)


class DeviceNotReadyError(Exception):
    pass


class DeviceManager:
    def __init__(self, adb):
        self.adb = adb

    def prepare_device(self):
        logger.info("Cihaz kontrol ediliyor...")

        devices = self.adb.devices()

        if not devices:
            raise DeviceNotReadyError("Hiç cihaz bulunamadı.")

        ready_devices = []

        for device in devices:
            if device["state"] == "device":
                ready_devices.append(device)

        if not ready_devices:
            raise DeviceNotReadyError("Cihaz hazır değil. unauthorized veya offline olabilir.")

        logger.info("Cihaz hazır: %s", ready_devices[0]["serial"])

    def install_app(self, apk_path):
        logger.info("APK kuruluyor: %s", apk_path)
        self.adb.install(apk_path)
        logger.info("APK kuruldu.")

    def launch_app(self, package_name):
        logger.info("Uygulama başlatılıyor: %s", package_name)
        self.adb.launch_app(package_name)
        logger.info("Uygulama başlatıldı.")

    def setup_for_analysis(self, apk_path, package_name):
        """Cihazı analiz için tam olarak hazırlar: hazırlık, kurulum, başlatma."""
        self.prepare_device()
        self.install_app(apk_path)
        self.launch_app(package_name)

    def cleanup(self, package_name):
        """Analiz sonrasında uygulamayı kaldırır."""
        try:
            self.adb.uninstall(package_name)
            logger.info("Uygulama kaldırıldı: %s", package_name)
        except Exception as e:
            logger.warning("Uygulama kaldırılamadı: %s", e)
