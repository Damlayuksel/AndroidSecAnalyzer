"""
androidsec/dynamic_analysis/frida/frida_manager.py

Frida ile runtime hooking ve izleme yönetimi.
Frida server ile iletişim kurarak uygulamanın çalışma zamanı
davranışlarını izler.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Frida scripts klasörü
SCRIPTS_DIR = Path(__file__).parent / "scripts"


class FridaError(Exception):
    """Frida işlemleri sırasında oluşan hatalar."""
    pass


class FridaManager:
    """
    Frida ile runtime hooking ve izleme yönetimi.

    Frida server'ın cihazda çalışıyor olması gerekir.

    Kullanım:
        manager = FridaManager()
        manager.attach("com.example.app")
        results = manager.run_script("crypto_hooks")
        manager.detach()
    """

    def __init__(self, adb=None):
        self.adb = adb
        self.session = None
        self.script = None
        self.device = None
        self._findings = []

    def _load_script_source(self, script_name: str) -> str:
        """
        Belirtilen Frida script dosyasını yükler.

        Args:
            script_name: Script dosya adı (uzantısız)

        Returns:
            JavaScript kaynak kodu

        Raises:
            FridaError: Script dosyası bulunamazsa
        """
        script_path = SCRIPTS_DIR / f"{script_name}.js"

        if not script_path.exists():
            raise FridaError(f"Frida script bulunamadı: {script_path}")

        with open(script_path, "r", encoding="utf-8") as f:
            return f.read()

    def attach(self, package_name: str):
        """
        Belirtilen uygulamaya Frida ile bağlanır.

        Args:
            package_name: Hedef uygulamanın paket adı

        Raises:
            FridaError: Frida yüklü değilse veya bağlantı başarısızsa
        """
        try:
            import frida
        except ImportError:
            raise FridaError(
                "Frida modülü yüklü değil. "
                "'pip install frida frida-tools' ile yükleyebilirsiniz."
            )

        import time

        try:
            logger.info("Frida cihaza bağlanıyor...")
            self.device = frida.get_usb_device(timeout=10)
            logger.info("Cihaz bulundu: %s", self.device.name)

            # ADB ile PID al, sonra attach et
            import subprocess as _sp
            pid_out = _sp.run(
                ["adb", "shell", "pidof", package_name],
                capture_output=True, text=True
            ).stdout.strip().split()

            if pid_out:
                pid = int(pid_out[0])
                logger.info("PID bulundu: %d — attach ediliyor...", pid)
                self.session = self.device.attach(pid)
                logger.info("Frida session oluşturuldu (pid=%d).", pid)
            else:
                raise FridaError(
                    f"Uygulama çalışmıyor: {package_name}. "
                    "Önce uygulamayı başlatın."
                )

        except frida.ServerNotRunningError:
            raise FridaError(
                "Frida server cihazda çalışmıyor. "
                "'adb shell /data/local/tmp/frida-server &' ile başlatın."
            )
        except Exception as e:
            raise FridaError(f"Frida bağlantı hatası: {str(e)}")

    def run_script(self, script_name: str) -> list:
        """
        Belirtilen Frida script'ini çalıştırır ve bulguları döndürür.

        Args:
            script_name: Script dosya adı ("crypto_hooks", "network_hooks")

        Returns:
            Bulgular listesi
        """
        if not self.session:
            raise FridaError("Önce attach() ile bir uygulamaya bağlanmalısınız.")

        source = self._load_script_source(script_name)

        if not source.strip():
            logger.warning("Script dosyası boş: %s", script_name)
            return []

        logger.info("Frida script çalıştırılıyor: %s", script_name)

        try:
            self.script = self.session.create_script(source)
            self.script.on("message", self._on_message)
            self.script.load()

            logger.info("Script yüklendi ve çalışıyor: %s", script_name)
            return self._findings

        except Exception as e:
            logger.error("Script çalıştırma hatası: %s", e)
            raise FridaError(f"Script çalıştırma hatası: {str(e)}")

    def _on_message(self, message, data):
        """Frida script'inden gelen mesajları işler."""
        if message["type"] == "send":
            payload = message.get("payload", {})

            if isinstance(payload, dict):
                finding = {
                    "category": payload.get("category", "M10: Extraneous Functionality"),
                    "severity": payload.get("severity", "MEDIUM"),
                    "title": payload.get("title", "Frida Hook Finding"),
                    "description": payload.get("description", str(payload)),
                    "recommendation": payload.get("recommendation", "Runtime davranışı incelenmelidir."),
                }
                self._findings.append(finding)
                logger.info("Frida bulgu: %s", finding["title"])
            else:
                logger.debug("Frida mesaj: %s", payload)

        elif message["type"] == "error":
            logger.error("Frida script hatası: %s", message.get("description", ""))

    def detach(self):
        """Frida session'ını kapatır."""
        if self.script:
            try:
                self.script.unload()
            except Exception:
                pass
            self.script = None

        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None

        logger.info("Frida session kapatıldı.")

    def get_findings(self) -> list:
        """Toplanan bulguları döndürür."""
        return list(self._findings)

    def clear_findings(self):
        """Bulguları temizler."""
        self._findings.clear()
