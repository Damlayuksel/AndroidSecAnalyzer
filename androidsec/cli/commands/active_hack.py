import click
import logging
import time
import subprocess

from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper
from androidsec.dynamic_analysis.device.manager import DeviceManager
from androidsec.active_hacking.automator import UIAutomator

logger = logging.getLogger(__name__)

@click.command('active-hack')
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('--duration', type=int, default=300, help='Fuzzing süresi (saniye)')
@click.option('--screen', default=None, help='Sadece bu ekranı tara (örn: "INPUT VALIDATIONS")')
@click.option('--watch', is_flag=True, default=False, help='İzleme modu: sen gezin, bot input görünce devralır')
@click.pass_context
def active_hack(ctx, apk_path, duration, screen, watch):
    """Otonom DAST Fuzzer — uygulamada kendi kendine gezinir ve zafiyet arar."""

    print("=" * 55)
    print("  AndroidSecAnalyzer — Active Hacking Modulu")
    print("=" * 55)

    try:
        # Paket adını bul
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True, text=True, check=True
            )
            package_name = result.stdout.split("name='")[1].split("'")[0]
        except Exception:
            package_name = click.prompt("Paket adi okunamadi. Manuel girin")

        print(f"  Hedef APK  : {apk_path}")
        print(f"  Paket      : {package_name}")
        print(f"  Sure       : {duration} saniye")
        if screen:
            print(f"  Hedef Ekran: {screen}")
        if watch:
            print(f"  Mod        : İzleme (sen gezin, bot devralır)")
        print("=" * 55)

        adb = ADBWrapper()
        manager = DeviceManager(adb)

        print("[*] Emulator kontrol ediliyor...")
        manager.prepare_device()
        print("[*] APK kuruluyor...")
        manager.install_app(apk_path)
        print("[*] Uygulama baslatiliyor...")
        manager.launch_app(package_name)
        time.sleep(2)

        print("[*] Fuzzer baslatiliyor...\n")

        automator = UIAutomator(adb)
        if watch:
            print("[*] İzleme modu — uygulamada istediğin ekrana git!")
            print("[*] Input alanı gördüğünde bot otomatik devralacak.\n")
            automator.watch(duration)
        else:
            automator.start(duration, target_screen=screen)

        elapsed = 0
        try:
            while elapsed < duration and automator._thread.is_alive():
                time.sleep(5)
                elapsed += 5
                found = len(automator.findings)
                print(f"[~] {elapsed}s / {duration}s — {found} zafiyet (kalan: {duration-elapsed}s)")
        except KeyboardInterrupt:
            print("\n[!] Durduruldu.")

        automator.stop()

        print("\n" + "=" * 55)
        print(f"  SONUC: {len(automator.findings)} zafiyet tespit edildi")
        print("=" * 55)
        for i, f in enumerate(automator.findings, 1):
            print(f"  [{i}] {f['description']}")

    except Exception as e:
        print(f"[HATA] {e}")
        ctx.exit(1)
