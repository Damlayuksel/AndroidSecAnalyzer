"""
AndroidSecAnalyzer Web Arayüzü
"""

import sys
import uuid        # her analiz için benzersiz ID üretmek için
import time
import shutil      # yüklenen APK dosyasını diske kopyalamak için
import threading   # analizi arka planda çalıştırmak için
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse

# bu dosya web/app.py, iki üst dizin projenin kökü (AndroidSecAnalyzer/)
PROJECT_ROOT = Path(__file__).parent.parent
# androidsec paketini import edebilmek için proje kökünü Python'un arama yoluna ekliyorum
sys.path.insert(0, str(PROJECT_ROOT))

# FastAPI uygulamasını oluşturuyorum, tüm endpoint'ler bu nesneye bağlanacak
app = FastAPI(title="AndroidSecAnalyzer")

# Yüklenen APK dosyalarının kaydedileceği klasör, yoksa otomatik oluşturuyorum
UPLOAD_DIR = PROJECT_ROOT / "output" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Çalışan/biten tüm analiz işlerini bellekte tutuyorum: { job_id: { status, findings, ... } }
jobs: Dict[str, Dict[str, Any]] = {}


# Analiz iş parçacıkları 

def run_static(job_id: str, apk_path: str):
    """Statik analizi arka planda çalıştırır, sonuçları jobs sözlüğüne yazar."""
    try:
        jobs[job_id]["status"] = "running"
        jobs[job_id]["phase"] = "JADX ile dekompile ediliyor..."

        # import burada yapılıyor çünkü her çağrıda yeni bir analyzer instance'ı lazım
        from androidsec.core.analyzer import AndroidSecAnalyzer
        analyzer = AndroidSecAnalyzer()

        # JADX dekompilasyonu + manifest/kod/sertifika/native analizini başlatıyorum
        result = analyzer.analyze(apk_path, analysis_type="static")

        jobs[job_id]["phase"] = "Rapor oluşturuluyor..."
        report_path = analyzer.generate_report(result, format="html")

        # Analiz bitti, tüm sonuçları job kaydına yazıyorum
        jobs[job_id].update({
            "status": "done",
            "phase": "Tamamlandı",
            "report_path": report_path,
            "risk_score": result.risk_score,
            "risk_level": result.risk_info.get("level", "UNKNOWN"),
            "total_findings": len(result.all_findings),
            "analysis_time": result.analysis_time,
            "statistics": result.statistics,
            "findings": result.all_findings,
        })
    except Exception as e:
        # Herhangi bir hata olursa frontend'e gösterilmek üzere kaydediyorum
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)


def _adb_filesystem_check(package_name: str) -> list:
    """ADB shell üzerinden uygulamanın runtime güvenlik durumunu kontrol eder."""
    import subprocess
    findings = []

    def shell(cmd, timeout=10):
        try:
            r = subprocess.run(["adb", "shell"] + cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout + r.stderr
        except Exception:
            return ""

    # 1. Debuggable mı? (run-as çalışıyorsa evet)
    out = shell(["run-as", package_name, "echo", "ok"], timeout=5)
    is_debuggable = "ok" in out
    if is_debuggable:
        findings.append({
            "category": "M1: Improper Platform Usage",
            "severity": "CRITICAL",
            "title": "Uygulama Debuggable Modda Çalışıyor",
            "description": "run-as komutu başarılı — uygulama production'da debuggable=true ile çalışıyor. "
                           "Saldırgan uygulamanın özel veri dizinine erişebilir.",
            "file": "AndroidManifest.xml",
            "recommendation": "android:debuggable='false' olarak ayarlanmalıdır.",
        })

    # 2. SharedPreferences dosyaları
    if is_debuggable:
        sp_out = shell(["run-as", package_name, "ls", f"/data/data/{package_name}/shared_prefs/"])
        if sp_out.strip() and "No such" not in sp_out:
            sp_files = [f.strip() for f in sp_out.strip().splitlines() if f.strip()]
            for sp_file in sp_files:
                content = shell(["run-as", package_name, "cat",
                                 f"/data/data/{package_name}/shared_prefs/{sp_file}"])
                sensitive_keys = ["password", "token", "secret", "key", "flag", "auth", "credential"]
                hits = [k for k in sensitive_keys if k in content.lower()]
                if hits:
                    findings.append({
                        "category": "M2: Insecure Data Storage",
                        "severity": "HIGH",
                        "title": f"SharedPreferences'ta Hassas Veri: {sp_file}",
                        "description": f"{sp_file} dosyasında hassas anahtar(lar) tespit edildi: {', '.join(hits)}. "
                                       "SharedPreferences düz metin olarak saklanır.",
                        "file": f"shared_prefs/{sp_file}",
                        "recommendation": "Hassas veriler EncryptedSharedPreferences ile şifrelenmelidir.",
                    })

        # 3. Veritabanları
        db_out = shell(["run-as", package_name, "ls", f"/data/data/{package_name}/databases/"])
        if db_out.strip() and "No such" not in db_out:
            db_files = [f.strip() for f in db_out.strip().splitlines() if f.strip() and not f.endswith("-journal")]
            if db_files:
                findings.append({
                    "category": "M2: Insecure Data Storage",
                    "severity": "MEDIUM",
                    "title": f"Şifresiz SQLite Veritabanı ({len(db_files)} adet)",
                    "description": f"Uygulama {len(db_files)} SQLite veritabanı kullanıyor: {', '.join(db_files[:3])}. "
                                   "Veritabanları şifrelenmemiş durumda.",
                    "file": "databases/",
                    "recommendation": "SQLCipher veya Room'un şifreleme desteği kullanılmalıdır.",
                })

    # 4. Backup aktif mi?
    backup_out = shell(["dumpsys", "package", package_name])
    if "allowBackup=true" in backup_out or "ALLOW_BACKUP" in backup_out:
        findings.append({
            "category": "M2: Insecure Data Storage",
            "severity": "MEDIUM",
            "title": "ADB Backup Aktif",
            "description": "Uygulama verisi 'adb backup' komutuyla dışarı çıkarılabilir. "
                           "Saldırgan cihaza fiziksel erişimle tüm uygulama verilerini kopyalayabilir.",
            "file": "AndroidManifest.xml",
            "recommendation": "android:allowBackup='false' olarak ayarlanmalıdır.",
        })

    # 5. Exported activity bypass testi
    exported_activities = [
        ("b25lActivity",             "Flag 1 — Giriş ekranı bypass"),
        ("QXV0aA",                   "Flag 2 — Authentication bypass"),
        ("FlagEighteenActivity",     "Flag 18 — Dışa açık ekran"),
        ("ExportedProtectedIntent",  "Protected Intent bypass"),
    ]
    bypassed = []
    for activity, desc in exported_activities:
        am_out = shell(["am", "start", "-n", f"{package_name}/.{activity}"], timeout=6)
        if "Starting" in am_out and "Error" not in am_out and "Exception" not in am_out:
            bypassed.append(f"{activity} ({desc})")

    if bypassed:
        findings.append({
            "category": "M6: Insecure Authorization",
            "severity": "HIGH",
            "title": f"Exported Activity Bypass ({len(bypassed)} adet)",
            "description": f"Aşağıdaki activity'ler herhangi bir uygulama tarafından doğrudan başlatılabildi: "
                           f"{', '.join(bypassed)}. Kimlik doğrulama atlatılabiliyor.",
            "file": "AndroidManifest.xml",
            "recommendation": "Gereksiz exported activity'ler android:exported='false' ile kapatılmalıdır.",
        })

    # 6. Uygulama izinleri runtime'da verilmiş mi?
    perm_out = shell(["dumpsys", "package", package_name])
    runtime_perms = []
    dangerous_perms = [
        ("READ_CONTACTS", "Kişi okuma"),
        ("READ_SMS", "SMS okuma"),
        ("READ_PHONE_STATE", "Telefon durumu"),
        ("ACCESS_FINE_LOCATION", "Hassas konum"),
        ("RECORD_AUDIO", "Ses kayıt"),
        ("READ_EXTERNAL_STORAGE", "Harici depolama okuma"),
        ("CAMERA", "Kamera erişimi"),
    ]
    for perm, label in dangerous_perms:
        if f"android.permission.{perm}" in perm_out and "granted=true" in perm_out:
            runtime_perms.append(label)

    if runtime_perms:
        findings.append({
            "category": "M1: Improper Platform Usage",
            "severity": "MEDIUM",
            "title": f"Tehlikeli İzinler Verilmiş ({len(runtime_perms)} adet)",
            "description": f"Uygulama şu izinlere runtime'da sahip: {', '.join(runtime_perms)}.",
            "file": "AndroidManifest.xml",
            "recommendation": "Yalnızca gerçekten gerekli izinler talep edilmelidir.",
        })

    # 7. Network Security Config — cleartext izinli mi?
    import os
    decompiled_dirs = []
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output", "decompiled")
    if os.path.isdir(output_dir):
        decompiled_dirs = [os.path.join(output_dir, d) for d in os.listdir(output_dir) if os.path.isdir(os.path.join(output_dir, d))]

    nsc_path = None
    for d in decompiled_dirs:
        candidate = os.path.join(d, "app", "src", "main", "res", "xml", "network_security_config.xml")
        if os.path.isfile(candidate):
            nsc_path = candidate
            break

    if nsc_path is None:
        findings.append({
            "category": "M3: Insecure Communication",
            "severity": "MEDIUM",
            "title": "Network Security Config Tanımlanmamış",
            "description": "network_security_config.xml bulunamadı. Android varsayılan olarak cleartext HTTP trafiğine izin verir.",
            "file": "AndroidManifest.xml",
            "recommendation": "res/xml/network_security_config.xml oluşturun ve cleartextTrafficPermitted='false' yapın.",
        })
    else:
        try:
            nsc_content = open(nsc_path, errors="ignore").read()
            if 'cleartextTrafficPermitted="true"' in nsc_content:
                findings.append({
                    "category": "M3: Insecure Communication",
                    "severity": "HIGH",
                    "title": "Cleartext HTTP Trafiğine İzin Veriliyor",
                    "description": "network_security_config.xml içinde cleartextTrafficPermitted='true' bulundu. "
                                   "Uygulama şifresiz HTTP trafiği gönderebilir; MITM saldırısına açık.",
                    "file": "res/xml/network_security_config.xml",
                    "recommendation": "cleartextTrafficPermitted='false' olarak değiştirin ve yalnızca HTTPS kullanın.",
                })
        except Exception:
            pass

    # 8. Firebase runtime bağlantısı (port 5228)
    netstat_out = shell(["netstat", "-an"], timeout=8)
    if ":5228" in netstat_out and "ESTABLISHED" in netstat_out:
        findings.append({
            "category": "M3: Insecure Communication",
            "severity": "INFO",
            "title": "Firebase Cloud Messaging Bağlantısı Aktif",
            "description": "Uygulama çalışırken Firebase FCM sunucusuna (port 5228) bağlantı kuruldu. "
                           "Uygulama anlık bildirim ve uzak yapılandırma için Google altyapısını kullanıyor.",
            "file": "runtime/network",
            "recommendation": "Firebase Remote Config ile gönderilen veriler doğrulanmalıdır.",
        })

    # 9. SSL pinning yok mu?
    has_pinning = False
    for d in decompiled_dirs:
        for dirpath, _, files in os.walk(d):
            for f in files:
                fpath = os.path.join(dirpath, f)
                if f.endswith((".java", ".kt")):
                    try:
                        if "CertificatePinner" in open(fpath, errors="ignore").read():
                            has_pinning = True
                            break
                    except Exception:
                        pass
            if has_pinning:
                break
        if has_pinning:
            break
    if not has_pinning:
        findings.append({
            "category": "M3: Insecure Communication",
            "severity": "MEDIUM",
            "title": "SSL/Certificate Pinning Uygulanmamış",
            "description": "Uygulamada SSL pinning tespit edilmedi. "
                           "Saldırgan, MITM proxy (Burp Suite, mitmproxy) kullanarak "
                           "uygulama trafiğini şifresi çözülmüş şekilde izleyebilir.",
            "file": "runtime/network",
            "recommendation": "OkHttp CertificatePinner veya network_security_config.xml ile "
                              "pin-set tanımlanmalıdır.",
        })

    return findings


def run_dynamic(job_id: str, apk_path: str):
    """Dinamik analizi arka planda çalıştırır, ADB üzerinden cihaza bağlanır."""
    try:
        jobs[job_id]["status"] = "running"
        jobs[job_id]["phase"] = "ADB cihaz kontrol ediliyor..."

        from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper
        from androidsec.dynamic_analysis.device.manager import DeviceManager
        from androidsec.dynamic_analysis.collectors.logcat import LogcatCollector
        from androidsec.dynamic_analysis.collectors.network import NetworkCollector
        from androidsec.dynamic_analysis.collectors.storage import StorageCollector
        from androidsec.core.analyzer import AndroidSecAnalyzer

        adb = ADBWrapper()

        # Cihaz hazırla
        manager = DeviceManager(adb)
        manager.prepare_device()

        # Paket adını al
        analyzer_core = AndroidSecAnalyzer()
        package_name  = analyzer_core._extract_package_name(apk_path)

        # APK kur (zaten kuruluysa atla)
        jobs[job_id]["phase"] = "APK cihaza yükleniyor..."
        import subprocess as _sp
        pm_out = _sp.run(["adb", "shell", "pm", "list", "packages", package_name],
                         capture_output=True, text=True, timeout=10).stdout
        if f"package:{package_name}" not in pm_out:
            manager.install_app(apk_path)

        # Uygulamayı başlat
        jobs[job_id]["phase"] = "Uygulama başlatılıyor..."
        manager.launch_app(package_name)

        # Logcat topla (30 saniye)
        jobs[job_id]["phase"] = "Runtime izleme aktif (30s)..."
        logcat = LogcatCollector(adb)
        logs   = logcat.collect(package_name=package_name, duration_seconds=30)

        # Logcat analizi
        jobs[job_id]["phase"] = "Ağ trafiği ve storage analizi yapılıyor..."
        net_findings     = NetworkCollector().analyze(logs)
        storage_findings = StorageCollector().analyze(logs)

        # ADB dosya sistemi kontrolü (kullanıcı etkileşimi gerektirmez)
        jobs[job_id]["phase"] = "Dosya sistemi ve izin kontrolü yapılıyor..."
        fs_findings = _adb_filesystem_check(package_name)

        all_findings = net_findings + storage_findings + fs_findings

        jobs[job_id]["phase"] = "Rapor olusturuluyor..."

        # Rapor için AnalysisResult benzeri yapı kur
        from androidsec.core.analyzer import AnalysisResult
        from androidsec.correlation.correlator import FindingCorrelator
        from androidsec.correlation.risk_calculator import RiskCalculator

        result = AnalysisResult(apk_path)
        result.dynamic_findings = all_findings
        result.analysis_time    = 30.0

        corr = FindingCorrelator().correlate(static_findings=[], dynamic_findings=all_findings)
        result.all_findings  = corr.get("all_findings", all_findings)
        result.by_owasp      = corr.get("by_owasp", {})
        result.statistics    = corr.get("statistics", {})

        risk = RiskCalculator().calculate(result.all_findings)
        result.risk_score = risk.get("score", 0.0)
        result.risk_info  = risk

        report_path = analyzer_core.generate_report(result, format="html")

        jobs[job_id].update({
            "status": "done",
            "phase": "Tamamlandı",
            "report_path": report_path,
            "risk_score": result.risk_score,
            "risk_level": result.risk_info.get("level", "UNKNOWN"),
            "total_findings": len(result.all_findings),
            "analysis_time": result.analysis_time,
            "statistics": result.statistics,
            "findings": result.all_findings,
        })
    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)


def run_active(job_id: str, apk_path: str):
    """Active hacking botunu arka planda çalıştırır."""
    try:
        import time
        from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper
        from androidsec.dynamic_analysis.device.manager import DeviceManager
        from androidsec.active_hacking.automator import UIAutomator
        from androidsec.core.analyzer import AndroidSecAnalyzer

        jobs[job_id]["status"] = "running"
        jobs[job_id]["phase"] = "ADB cihaz kontrol ediliyor..."

        adb = ADBWrapper()
        if not adb.is_device_connected():
            raise Exception("Emülatör bağlı değil. ADB bağlantısını kontrol edin.")

        manager = DeviceManager(adb)
        manager.prepare_device()

        jobs[job_id]["phase"] = "APK kuruluyor..."
        analyzer_core = AndroidSecAnalyzer()
        package_name = analyzer_core._extract_package_name(apk_path)

        # Uygulama zaten kuruluysa install adımını atla (120s timeout'u önler)
        import subprocess as _sp
        pm_out = _sp.run(["adb", "shell", "pm", "list", "packages", package_name],
                         capture_output=True, text=True, timeout=10).stdout
        if f"package:{package_name}" not in pm_out:
            manager.install_app(apk_path)
        else:
            jobs[job_id]["phase"] = "Uygulama zaten kurulu, kurlum atlanıyor..."

        jobs[job_id]["phase"] = "Uygulama başlatılıyor..."
        # Önce force-stop, sonra main activity'yi component adıyla doğrudan aç
        _sp.run(["adb", "shell", "am", "force-stop", package_name], capture_output=True, timeout=10)
        time.sleep(1)
        # Main activity'yi pkg resolve ile bul
        resolve = _sp.run(
            ["adb", "shell", "cmd", "package", "resolve-activity", "--brief",
             "-c", "android.intent.category.LAUNCHER",
             "-a", "android.intent.action.MAIN", package_name],
            capture_output=True, text=True, timeout=10
        ).stdout
        main_comp = None
        for line in resolve.splitlines():
            line = line.strip()
            if line.startswith(package_name):
                main_comp = line
                break
        if main_comp:
            _sp.run(["adb", "shell", "am", "start", "-n", main_comp],
                    capture_output=True, timeout=15)
        else:
            manager.launch_app(package_name)
        time.sleep(3)

        jobs[job_id]["phase"] = "Bot aktif — ekranlar taranıyor..."
        bot = UIAutomator(adb)
        jobs[job_id]["_bot"] = bot   # cancel için referans
        bot.start(duration=120)

        # Her 3 saniyede anlık bulguları jobs'a yaz; cancel geldiyse çık
        elapsed = 0
        while elapsed < 120 and bot._thread.is_alive():
            time.sleep(3)
            elapsed += 3
            jobs[job_id]["findings"] = bot.findings.copy()
            jobs[job_id]["total_findings"] = len(bot.findings)
            jobs[job_id]["phase"] = f"Bot çalışıyor... {elapsed}s / 120s — {len(bot.findings)} zafiyet"
            if jobs[job_id].get("cancelled"):
                bot.stop()
                break

        bot.stop()

        jobs[job_id].update({
            "status":         "done",
            "phase":          "Tamamlandı",
            "findings":       bot.findings,
            "total_findings": len(bot.findings),
            "risk_score":     _risk_score(bot.findings),
            "risk_level":     _risk_level(bot.findings),
            "analysis_time":  120.0,
            "statistics":     _sev_stats(bot.findings),
        })
    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)


# Endpoints

@app.post("/upload")
async def upload_apk(
    file: UploadFile = File(...),
    analysis_type: str = Form("static"),  # formdan "static" veya "dynamic" geliyor
):
    # sadece .apk dosyası kabul ediyorum
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Sadece .apk dosyası yüklenebilir.")
    if analysis_type not in ("static", "dynamic", "active"):
        raise HTTPException(status_code=400, detail="Geçersiz analiz tipi.")

    # aynı isimli dosyalar çakışmasın diye job_id'yi dosya adına ekliyorum
    job_id = str(uuid.uuid4())[:8]
    apk_dest = UPLOAD_DIR / f"{job_id}_{file.filename}"

    # yüklenen dosyayı diske yazıyorum (chunk'lar halinde, büyük APK'larda bellek patlamasın)
    with open(apk_dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # bu analiz için bellekte bir kayıt oluşturuyorum
    jobs[job_id] = {
        "status": "queued",
        "phase": "Sıraya alındı",
        "filename": file.filename,
        "analysis_type": analysis_type,
        "apk_path": str(apk_dest),
    }

    # analiz tipine göre doğru fonksiyonu seçip thread olarak başlatıyorum
    # daemon=True → ana uygulama kapanırsa thread de kapanır
    if analysis_type == "static":
        target = run_static
    elif analysis_type == "dynamic":
        target = run_dynamic
    else:
        target = run_active
    threading.Thread(target=target, args=(job_id, str(apk_dest)), daemon=True).start()

    # analiz arka planda devam ederken hemen job_id'yi döndürüyorum
    return {"job_id": job_id}


@app.get("/status/{job_id}")
async def get_status(job_id: str):
    """Frontend her 1.2 saniyede bu endpoint'i çağırarak analiz durumunu takip ediyor."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="İş bulunamadı.")
    job = jobs[job_id]
    return {
        "status": job["status"],            # queued / running / done / error
        "phase": job.get("phase", ""),      # ekranda gösterilen aşama metni
        "filename": job.get("filename", ""),
        "analysis_type": job.get("analysis_type", "static"),
        "risk_score": job.get("risk_score"),
        "risk_level": job.get("risk_level"),
        "total_findings": job.get("total_findings"),
        "analysis_time": job.get("analysis_time"),
        "statistics": job.get("statistics"),
        "findings": job.get("findings", []),
        "error": job.get("error"),
    }


def _risk_score(findings: list) -> float:
    weights = {"CRITICAL": 2.0, "HIGH": 1.2, "MEDIUM": 0.6, "LOW": 0.2, "INFO": 0.0}
    return min(sum(weights.get(f.get("severity", ""), 0) for f in findings), 10.0)

def _risk_level(findings: list) -> str:
    sevs = {f.get("severity", "") for f in findings}
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if level in sevs:
            return level
    return "LOW"

def _sev_stats(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "")
        if sev in counts:
            counts[sev] += 1
    return {"by_severity": counts}


@app.post("/cancel/{job_id}")
async def cancel_job(job_id: str):
    """Çalışan analizi durdurur."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="İş bulunamadı.")
    job = jobs[job_id]
    if job.get("status") != "running":
        return {"ok": False, "reason": "Zaten durmuş."}
    job["cancelled"] = True
    bot = job.get("_bot")
    if bot:
        bot.stop()
    findings = job.get("findings", [])
    job.update({
        "status":        "done",
        "phase":         "Kullanıcı tarafından durduruldu.",
        "findings":      findings,
        "total_findings": len(findings),
        "risk_score":    _risk_score(findings),
        "risk_level":    _risk_level(findings),
        "analysis_time": 0.0,
        "statistics":    _sev_stats(findings),
    })
    return {"ok": True}


@app.get("/device-status")
async def device_status():
    """Dinamik analiz sekmesindeki cihaz göstergesi için ADB bağlantısını kontrol ediyorum."""
    try:
        from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper
        adb = ADBWrapper()
        connected = adb.is_device_connected()
        # devices() metodu {"serial": ..., "state": ...} listesi döndürüyor
        devices = [d["serial"] for d in adb.devices() if d["state"] == "device"] if connected else []
        return {"connected": connected, "devices": devices}
    except Exception:
        # ADB kurulu değilse veya herhangi bir hata olursa uygulamayı çöktürmüyorum
        return {"connected": False, "devices": []}


@app.get("/report/{job_id}")
async def get_report(job_id: str):
    """Analiz tamamlandıktan sonra oluşturulan HTML raporu tarayıcıya gönderiyorum."""
    if job_id not in jobs or jobs[job_id]["status"] != "done":
        raise HTTPException(status_code=404, detail="Rapor henüz hazır değil.")
    return FileResponse(jobs[job_id]["report_path"], media_type="text/html")


@app.get("/download/{job_id}")
async def download_report(job_id: str):
    """Raporu indirme olarak gönderiyorum — tarayıcı açmak yerine kaydeder."""
    if job_id not in jobs or jobs[job_id]["status"] != "done":
        raise HTTPException(status_code=404, detail="Rapor henüz hazır değil.")
    report_path = jobs[job_id]["report_path"]
    filename = Path(report_path).name
    # Content-Disposition: attachment → tarayıcı dosyayı açmak yerine indirir
    return FileResponse(
        report_path,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/download/{job_id}/json")
async def download_json_report(job_id: str):
    """Analiz sonuçlarını JSON formatında indirir."""
    if job_id not in jobs or jobs[job_id]["status"] != "done":
        raise HTTPException(status_code=404, detail="Rapor henüz hazır değil.")
    import json, tempfile
    job = jobs[job_id]
    data = {
        "job_id": job_id,
        "filename": job.get("filename"),
        "analysis_type": job.get("analysis_type"),
        "risk_score": job.get("risk_score"),
        "risk_level": job.get("risk_level"),
        "total_findings": job.get("total_findings"),
        "analysis_time": job.get("analysis_time"),
        "statistics": job.get("statistics"),
        "findings": job.get("findings", []),
    }
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8")
    json.dump(data, tmp, ensure_ascii=False, indent=2)
    tmp.close()
    stem = Path(job.get("filename", "report")).stem
    return FileResponse(
        tmp.name,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{stem}_report.json"'},
    )


@app.get("/", response_class=HTMLResponse)
async def index():
    """Ana sayfa — index.html'i okuyup tarayıcıya gönderiyorum."""
    return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
