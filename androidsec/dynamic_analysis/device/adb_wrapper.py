"""
androidsec/dynamic_analysis/device/adb_wrapper.py

Python'dan temel ADB komutlarını çalıştırmak için basit katman.
"""

import logging
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class ADBError(Exception):
    pass


class ADBWrapper:
    def __init__(self, adb_path="adb", default_timeout=60):
        self.adb_path = adb_path
        self.default_timeout = default_timeout

    def _run(self, *args, timeout=None, check=True):
        cmd = [self.adb_path] + list(args)

        if timeout is None:
            timeout = self.default_timeout

        try:
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )
        except FileNotFoundError:
            raise ADBError("ADB bulunamadı. Terminalde 'adb' çalışıyor mu kontrol et.")
        except subprocess.TimeoutExpired:
            raise ADBError("ADB komutu çok uzun sürdü ve zaman aşımına uğradı.")

        if check and result.returncode != 0:
            raise ADBError(
                f"ADB komutu başarısız.\n"
                f"Komut: {' '.join(cmd)}\n"
                f"Hata: {(result.stderr or '').strip()}"
            )

        return result

    def _ensure_parent_dir(self, output_path):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def devices(self):
        result = self._run("devices", check=False)
        lines = (result.stdout or "").strip().splitlines()

        device_list = []

        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) == 2:
                device_list.append({
                    "serial": parts[0],
                    "state": parts[1]
                })

        return device_list

    def is_device_connected(self):
        for device in self.devices():
            if device["state"] == "device":
                return True
        return False

    def assert_device_connected(self):
        if not self.is_device_connected():
            raise ADBError("Bağlı cihaz bulunamadı. 'adb devices' çıktısını kontrol et.")

    def install(self, apk_path, timeout=120):
        apk = Path(apk_path)

        if not apk.exists():
            raise FileNotFoundError(f"APK bulunamadı: {apk_path}")

        self.assert_device_connected()

        logger.info("APK yükleniyor: %s", apk_path)

        try:
            result = self._run("install", "-r", "-g", "--bypass-low-target-sdk-block", str(apk), timeout=timeout)
        except ADBError:
         
            result = self._run("install", "-r", "-g", str(apk), timeout=timeout)

        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        if "Failure" in stdout or "Failure" in stderr:
            raise ADBError(f"APK kurulamadı.\nStdout: {stdout}\nStderr: {stderr}")

        return stdout

    def launch_app(self, package_name, timeout=30):
        self.assert_device_connected()

        logger.info("Uygulama başlatılıyor: %s", package_name)

        result = self._run(
            "shell",
            "monkey",
            "-p",
            package_name,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
            timeout=timeout
        )

        stdout = (result.stdout or "").strip()

        if "monkey aborted" in stdout.lower():
            raise ADBError(f"Uygulama açılamadı: {stdout}")

        return stdout

    def clear_logcat(self):
        self.assert_device_connected()
        self._run("logcat", "-c")

    def get_logcat_dump(self, timeout=30, package_name: str = None):
        """
        Logcat çıktısını alır.
        package_name verilirse sadece o paketin PID'ine ait loglar filtrelenir.
        """
        self.assert_device_connected()

        if package_name:
            # Paketin PID'ini bul
            try:
                pid_result = self._run("shell", "pidof", package_name, check=False)
                pid = (pid_result.stdout or "").strip().split()[0]
                if pid:
                    result = self._run("logcat", "-d", "--pid", pid, timeout=timeout)
                    return (result.stdout or "").strip()
            except Exception:
                pass

        result = self._run("logcat", "-d", timeout=timeout)
        return (result.stdout or "").strip()

    def logcat(self, output_path, duration_seconds=10, clear_first=True):
        self.assert_device_connected()

        if clear_first:
            self.clear_logcat()

        path = self._ensure_parent_dir(output_path)

        cmd = [self.adb_path, "logcat"]

        try:
            with open(path, "w", encoding="utf-8") as file:
                process = subprocess.Popen(
                    cmd,
                    stdout=file,
                    stderr=subprocess.PIPE,
                    text=True
                )

                time.sleep(duration_seconds)

                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

        except OSError:
            raise ADBError(f"Log dosyasına yazılamadı: {path}")

        return str(path)

    def get_package_info(self, package_name, timeout=15):
        """Cihazda yüklü paketin bilgilerini döndürür."""
        self.assert_device_connected()
        result = self._run(
            "shell", "dumpsys", "package", package_name, timeout=timeout
        )
        return (result.stdout or "").strip()

    def uninstall(self, package_name, timeout=30):
        """Cihazdan uygulama kaldırır."""
        self.assert_device_connected()
        logger.info("Uygulama kaldırılıyor: %s", package_name)
        result = self._run("uninstall", package_name, timeout=timeout, check=False)
        return (result.stdout or "").strip()

    def shell(self, *args, timeout=None):
        self.assert_device_connected()
        result = self._run("shell", *args, timeout=timeout)
        return (result.stdout or "").strip()
