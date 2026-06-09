# AndroidSecAnalyzer — Kullanım Kılavuzu

## İçindekiler

1. [Gereksinimler](#gereksinimler)
2. [Kurulum](#kurulum)
3. [Web Arayüzü ile Kullanım](#web-arayüzü-ile-kullanım)
4. [Analiz Modları](#analiz-modları)
5. [Raporu İndirme](#raporu-indirme)
6. [Dinamik Analiz için Ek Kurulum](#dinamik-analiz-için-ek-kurulum)
7. [Sık Karşılaşılan Sorunlar](#sık-karşılaşılan-sorunlar)

---

## Gereksinimler

| Araç | Versiyon | Zorunlu mu? |
|------|----------|-------------|
| Python | 3.10 veya üstü | Evet |
| JADX | Herhangi | Evet (statik analiz) |
| ADB (Android SDK) | Herhangi | Hayır (sadece dinamik analiz) |
| Frida | Herhangi | Hayır (sadece dinamik analiz) |

### Python kurulu mu kontrol et

```bash
python3 --version
```

`3.10` veya üstü çıkıyorsa devam edebilirsin.

### JADX kurulumu (macOS)

```bash
brew install jadx
```

JADX, APK dosyalarını Java kaynak koduna dönüştürmek için kullanılır. Statik analiz için zorunludur.

---

## Kurulum

### 1. Projeyi indir

```bash
git clone https://github.com/damlayuksel/AndroidSecAnalyzer.git
cd AndroidSecAnalyzer
```

### 2. Sanal ortam oluştur ve aktif et

```bash
python3 -m venv venv
source venv/bin/activate
```

> Windows kullanıyorsan: `venv\Scripts\activate`

### 3. Gerekli paketleri yükle

```bash
pip install -r requirements.txt
```

---

## Web Arayüzü ile Kullanım

### Sunucuyu başlat

```bash
cd web
uvicorn app:app --reload --port 8000
```

### Tarayıcıda aç

```
http://localhost:8000
```

Sayfa açıldıktan sonra:

1. **Analiz modunu seç** — Statik Analiz, Dinamik Analiz veya Active Hacking
2. **APK dosyasını yükle** — Sürükle bırak ya da "Dosya Seç" butonuna tıkla
3. **Analizi bekle** — İlerleme çubuğu ve aşama bilgisi canlı olarak güncellenir
4. **Sonuçları incele** — Risk skoru, zafiyet listesi ve öneriler ekranda gösterilir
5. **Raporu indir** — HTML veya JSON formatında rapor indirebilirsin

---

## Analiz Modları

### Statik Analiz

APK'yı çalıştırmadan analiz eder. İnternet bağlantısı veya cihaz gerekmez.

- AndroidManifest.xml analizi (izinler, güvenlik bayrakları)
- Kaynak kod tarama (zayıf kriptografi, hardcoded secret'lar, SQL injection)
- Sertifika doğrulama
- Native `.so` kütüphane analizi

### Dinamik Analiz

Uygulamayı çalışırken izler. Android emülatör veya fiziksel cihaz gerektirir.

- Ağ trafiği izleme (HTTP/HTTPS)
- Frida ile runtime hook'lama
- Logcat üzerinden veri sızıntısı tespiti

> Dinamik analiz için önce [Dinamik Analiz için Ek Kurulum](#dinamik-analiz-için-ek-kurulum) bölümünü oku.

### Active Hacking

UIAutomator botu ile emülatördeki uygulamaya otomatik payload dener.

- SQL Injection
- XSS
- Auth bypass denemeleri

> Active Hacking için de Android emülatör ve ADB bağlantısı gereklidir.

---

## Raporu İndirme

Analiz tamamlandıktan sonra sayfanın altında üç buton çıkar:

| Buton | Açıklama |
|-------|----------|
| **Raporu Görüntüle** | HTML raporu yeni sekmede açar |
| **Raporu İndir** | HTML raporu bilgisayarına kaydeder |
| **JSON İndir** | Ham veriyi JSON olarak kaydeder |

Raporlar `output/reports/` klasörüne de otomatik kaydedilir.

---

## Dinamik Analiz için Ek Kurulum

### 1. Android Emülatör veya Fiziksel Cihaz

- [Android Studio](https://developer.android.com/studio) kurarak emülatör oluşturabilirsin
- Fiziksel cihaz kullanıyorsan **USB Hata Ayıklama** modunu aç:
  `Ayarlar → Geliştirici Seçenekleri → USB Hata Ayıklama`

### 2. ADB kurulumu (macOS)

```bash
brew install android-platform-tools
```

Bağlantıyı test et:

```bash
adb devices
```

Çıktıda cihazın görünmesi gerekir.

### 3. Frida kurulumu

```bash
pip install frida frida-tools
```

Cihaza Frida server yükle:

```bash
# Cihaz mimarisini öğren
adb shell getprop ro.product.cpu.abi

# frida.re/releases adresinden uygun frida-server'ı indir
# Cihaza kopyala ve çalıştır
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

---

## Sık Karşılaşılan Sorunlar

### `ModuleNotFoundError: No module named 'fastapi'`

Sanal ortamı aktif etmeyi unutmuşsundur:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### `JADX bulunamadı` hatası

JADX kurulu değil veya PATH'te değil:

```bash
brew install jadx
which jadx  # /opt/homebrew/bin/jadx çıkması gerekir
```

### `Cihaz bulunamadı` (Dinamik Analiz)

ADB bağlantısını kontrol et:

```bash
adb kill-server
adb start-server
adb devices
```

Cihazda "USB Hata Ayıklama'ya izin ver?" sorusu çıkmış olabilir — **İzin Ver** de.

### Port 8000 kullanımda

Farklı bir port dene:

```bash
uvicorn app:app --reload --port 8080
```

---

> Herhangi bir sorun için GitHub Issues üzerinden bildirim oluşturabilirsin.
