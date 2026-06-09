"""
Test Fixtures - Mock Data
Testler için kullanılacak sahte veriler

Bu dosya test senaryolarında kullanılan örnek veriler içerir:
1. Örnek AndroidManifest.xml
2. Örnek sertifika bilgileri
3. Örnek Java kodu (zafiyetli)
4. Yardımcı fonksiyonlar
"""

import os
import zipfile
import tempfile
from pathlib import Path


# Örnek AndroidManifest.xml

SAMPLE_MANIFEST_SECURE = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.secureapp"
    android:versionCode="1"
    android:versionName="1.0.0">

    <uses-sdk
        android:minSdkVersion="26"
        android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application
        android:allowBackup="false"
        android:debuggable="false"
        android:usesCleartextTraffic="false">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity
            android:name=".SettingsActivity"
            android:exported="false" />

    </application>
</manifest>
"""

SAMPLE_MANIFEST_VULNERABLE = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerableapp"
    android:versionCode="1"
    android:versionName="2.0.0">

    <uses-sdk
        android:minSdkVersion="16"
        android:targetSdkVersion="25" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity
            android:name=".AdminSettingsActivity"
            android:exported="true" />

        <activity
            android:name=".DebugActivity"
            android:exported="true" />

        <service
            android:name=".BackgroundService"
            android:exported="true" />

        <receiver
            android:name=".BootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <provider
            android:name=".DataProvider"
            android:exported="true"
            android:authorities="com.example.vulnerableapp.provider" />

    </application>
</manifest>
"""

SAMPLE_MANIFEST_MINIMAL = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.minimal">

    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


# Örnek Java Kodu (Zafiyetli)

SAMPLE_JAVA_VULNERABLE = """\
package com.example.vulnerableapp;

import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import java.util.Random;
import android.database.sqlite.SQLiteDatabase;

public class MainActivity {

    // Hardcoded API key
    private static final String API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
    private static final String API_SECRET = "my_super_secret_api_key_12345678901234567890";
    private String password = "admin123";

    // Zayıf hash algoritması
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    // Zayıf şifreleme
    public void encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        // ...
    }

    // ECB mode kullanımı
    public void encryptAES(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ...
    }

    // Insecure Random
    public int generateToken() {
        Random random = new Random();
        return random.nextInt(1000000);
    }

    // Hardcoded key
    byte[] encryptionKey = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    // SQL Injection
    public void searchUser(SQLiteDatabase db, String input) {
        db.execSQL("SELECT * FROM users WHERE name = '" + input + "'");
        db.rawQuery("SELECT * FROM accounts WHERE id = " + input, null);
    }

    // WebView güvenlik sorunları
    public void setupWebView(WebView webView) {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setAllowFileAccess(true);
    }

    // Hassas veri loglama
    public void login(String username, String pwd) {
        Log.d("Auth", "password: " + pwd);
        Log.d("Auth", "token: " + getToken());
    }

    private String getToken() {
        return "abc123";
    }
}
"""

SAMPLE_JAVA_SECURE = """\
package com.example.secureapp;

import android.os.Bundle;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import java.security.SecureRandom;

public class SecureActivity {

    // SHA-256 kullanımı (güvenli)
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(password.getBytes());
    }

    // AES-GCM kullanımı (güvenli)
    public void encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // ...
    }

    // SecureRandom kullanımı (güvenli)
    public int generateToken() {
        SecureRandom random = new SecureRandom();
        return random.nextInt(1000000);
    }
}
"""


# Örnek Sertifika Bilgileri

SAMPLE_CERT_INFO_NORMAL = {
    "subject": "CN=MyCompany, O=MyOrganization",
    "issuer": "CN=MyCompany, O=MyOrganization",
    "valid_from": "2023-01-01 00:00:00",
    "valid_to": "2053-01-01 00:00:00",
    "serial_number": "1234567890",
    "signature_algorithm": "SHA256withRSA",
    "version": 3,
    "fingerprint_sha256": "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90",
    "cert_file": "META-INF/CERT.RSA",
    "common_name": "MyCompany",
    "organization": "MyOrganization",
}

SAMPLE_CERT_INFO_EXPIRED = {
    "subject": "CN=OldApp, O=OldOrg",
    "issuer": "CN=OldApp, O=OldOrg",
    "valid_from": "2010-01-01 00:00:00",
    "valid_to": "2020-01-01 00:00:00",
    "serial_number": "9876543210",
    "signature_algorithm": "SHA1withRSA",
    "version": 3,
    "fingerprint_sha256": "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:11:22",
    "cert_file": "META-INF/CERT.RSA",
    "common_name": "OldApp",
}

SAMPLE_CERT_INFO_DEBUG = {
    "subject": "CN=Android Debug, O=Android, C=US",
    "issuer": "CN=Android Debug, O=Android, C=US",
    "valid_from": "2024-01-01 00:00:00",
    "valid_to": "2054-01-01 00:00:00",
    "serial_number": "1",
    "signature_algorithm": "SHA256withRSA",
    "version": 3,
    "fingerprint_sha256": "38:A8:62:A6:F9:EC:3B:32:BD:64:40:00:6F:5D:AF:01:FA:BF:46:B8:B5:41:94:FB:EF:61:BF:AD:0B:E5:A6:8D",
    "cert_file": "META-INF/CERT.RSA",
    "common_name": "Android Debug",
}

SAMPLE_CERT_INFO_WEAK_ALGO = {
    "subject": "CN=WeakAlgo, O=TestOrg",
    "issuer": "CN=WeakAlgo, O=TestOrg",
    "valid_from": "2023-01-01 00:00:00",
    "valid_to": "2053-01-01 00:00:00",
    "serial_number": "5555",
    "signature_algorithm": "MD5withRSA",
    "version": 3,
    "fingerprint_sha256": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
    "cert_file": "META-INF/CERT.RSA",
}

SAMPLE_CERT_INFO_SHORT_VALIDITY = {
    "subject": "CN=ShortValidity, O=TestOrg",
    "issuer": "CN=ShortValidity, O=TestOrg",
    "valid_from": "2023-01-01 00:00:00",
    "valid_to": "2033-01-01 00:00:00",
    "serial_number": "9999",
    "signature_algorithm": "SHA256withRSA",
    "version": 3,
    "fingerprint_sha256": "CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB",
    "cert_file": "META-INF/CERT.RSA",
}


# Yardımcı Fonksiyonlar

def create_test_manifest_file(content: str = SAMPLE_MANIFEST_VULNERABLE) -> str:
    """
    Geçici AndroidManifest.xml dosyası oluştur

    Args:
        content: Manifest XML içeriği

    Returns:
        Geçici dosya yolu
    """
    tmp = tempfile.NamedTemporaryFile(
        suffix='.xml', delete=False, mode='w', encoding='utf-8'
    )
    tmp.write(content)
    tmp.close()
    return tmp.name


def create_test_apk(
    manifest_content: str = SAMPLE_MANIFEST_VULNERABLE,
    java_files: dict = None,
    include_cert: bool = True,
    include_so: bool = False,
) -> str:
    """
    Test için sahte APK (ZIP) dosyası oluştur

    APK bir ZIP dosyasıdır, bu fonksiyon test için gerekli dosyaları
    içeren minimal bir ZIP oluşturur.

    Args:
        manifest_content: AndroidManifest.xml içeriği
        java_files: Java dosyaları dict {path: content}
        include_cert: META-INF/CERT.RSA dahil edilsin mi
        include_so: .so dosyaları dahil edilsin mi

    Returns:
        Geçici APK dosyası yolu
    """
    tmp = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
    tmp_path = tmp.name
    tmp.close()

    with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # AndroidManifest.xml ekle (metin olarak)
        zf.writestr('AndroidManifest.xml', manifest_content)

        # META-INF/CERT.RSA ekle (sahte sertifika)
        if include_cert:
            # Minimum geçerli PKCS#7 container'a benzer veri
            # CN= ve O= stringleri içerir (string arama için)
            cert_data = (
                b'\x30\x82\x02\x00'  # PKCS#7 header
                + b'\x00' * 32
                + b'CN=TestApp\x00'
                + b'O=TestOrg\x00'
                + b'sha256WithRSAEncryption\x00'
                + b'\x00' * 100
            )
            zf.writestr('META-INF/CERT.RSA', cert_data)
            zf.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')

        # .so dosyaları ekle
        if include_so:
            # Minimal ELF header (64-bit, little-endian, shared object)
            elf_header = (
                b'\x7fELF'                # ELF magic
                + b'\x02'                  # 64-bit
                + b'\x01'                  # little-endian
                + b'\x01'                  # ELF version
                + b'\x00' * 9             # padding
                + b'\x03\x00'             # ET_DYN (shared object / PIE)
                + b'\xB7\x00'             # ARM AARCH64
                + b'\x00' * 48            # rest of header
                + b'strcpy\x00'           # dangerous function
                + b'system\x00'           # dangerous function
                + b'\x00' * 100
            )
            zf.writestr('lib/arm64-v8a/libnative.so', elf_header)
            zf.writestr('lib/armeabi-v7a/libnative.so',
                         b'\x7fELF\x01\x01\x01' + b'\x00' * 9
                         + b'\x03\x00' + b'\x28\x00' + b'\x00' * 48
                         + b'\x00' * 100)

    return tmp_path


def create_test_decompiled_dir(
    java_files: dict = None,
    manifest_content: str = SAMPLE_MANIFEST_VULNERABLE,
    include_so: bool = False,
) -> str:
    """
    Test için dekompile edilmiş APK klasörü oluştur

    Args:
        java_files: Java dosyaları dict {path: content}
        manifest_content: AndroidManifest.xml içeriği
        include_so: .so dosyaları dahil edilsin mi

    Returns:
        Geçici klasör yolu
    """
    tmp_dir = tempfile.mkdtemp(prefix='androidsec_test_')

    # AndroidManifest.xml
    manifest_path = Path(tmp_dir) / "AndroidManifest.xml"
    manifest_path.write_text(manifest_content, encoding='utf-8')

    # Java dosyaları
    if java_files is None:
        java_files = {
            "smali/com/example/vulnerableapp/MainActivity.java": SAMPLE_JAVA_VULNERABLE,
            "smali/com/example/secureapp/SecureActivity.java": SAMPLE_JAVA_SECURE,
        }

    for rel_path, content in java_files.items():
        file_path = Path(tmp_dir) / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding='utf-8')

    # .so dosyaları
    if include_so:
        so_dir = Path(tmp_dir) / "lib" / "arm64-v8a"
        so_dir.mkdir(parents=True, exist_ok=True)

        # Minimal ELF
        elf_data = (
            b'\x7fELF\x02\x01\x01' + b'\x00' * 9
            + b'\x03\x00' + b'\xB7\x00'
            + b'\x00' * 48
            + b'http://evil.example.com/c2\x00'
            + b'strcpy\x00'
            + b'\x00' * 100
        )
        (so_dir / "libnative.so").write_bytes(elf_data)

    return tmp_dir


def cleanup_test_file(path: str) -> None:
    """Geçici test dosyasını sil"""
    try:
        os.unlink(path)
    except OSError:
        pass


def cleanup_test_dir(path: str) -> None:
    """Geçici test klasörünü sil"""
    import shutil
    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass
