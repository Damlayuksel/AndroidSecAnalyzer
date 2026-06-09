"""
UIAutomator tabanlı otomatik DAST fuzzer.
Emülatördeki uygulamada ekranları tarayarak SQL Injection,
XSS ve diğer zafiyet payload'larını dener.
"""

import logging
import subprocess
import time
import re
import xml.etree.ElementTree as ET
from threading import Thread, Event

from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper

logger = logging.getLogger(__name__)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter('\033[1m[%(levelname)s]\033[0m %(message)s'))
    logger.addHandler(_h)
    logger.setLevel(logging.DEBUG)


PAYLOADS = {
    # Input Validation / SQL Injection 
    "sql": [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin' --",
        "' OR 1=1#",
        "1 OR 1=1",
        "' UNION SELECT null,null --",
        "admin --",
        "1 UNION SELECT 1,2,3",
    ],

    #  XSS / Script Injection 
    # < ve > içerenler clipboard yöntemiyle gönderilir (_type metoduna bakın)
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "javascript:alert(document.cookie)",
        "onerror=alert(1)",
        "alert(1)",
        "prompt(1)",
    ],

    #  Authentication / Authorization Bypass 
    "auth": [
        "admin",
        "admin:admin",
        "admin:password",
        "root",
        "administrator",
        "guest",
        "test:test",
        "' OR '1'='1",
        "true",
        "null",
    ],

    #  API Manipulation 
    "api": [
        "../../../etc/passwd",
        "../../config",
        "null",
        "undefined",
        "{}",
        "[]",
        "<>",
        "999999999",
        "-1",
        "0",
    ],

    # Deep Link Abuse 
    "deeplink": [
        "javascript://",
        "file:///data/data/",
        "file:///etc/passwd",
        "http://evil.example.com",
        "content://",
    ],

    # Local Storage / Insecure Data 
    "storage": [
        "/data/data/",
        "/sdcard/",
        "shared_prefs",
        "databases/",
        "../../../shared_prefs/",
    ],

    #  Input Overflow / Fuzzing 
    "overflow": [
        "A" * 100,
        "1" * 200,
    ],
}

# Alan türü tespiti için anahtar kelimeler

FIELD_TYPE_MAP = {
    "auth":     ["username", "kullanici", "user", "email", "mail",
                 "password", "sifre", "pass", "pwd", "pin", "login",
                 "signin", "credential", "account", "hesap"],
    "sql":      ["search", "query", "ara", "flag", "keyword",
                 "filter", "find", "input", "text"],
    "xss":      ["name", "isim", "ad", "comment", "yorum", "message",
                 "mesaj", "description", "note", "bio", "display", "xss"],
    "api":      ["url", "link", "api", "id", "token", "key", "code",
                 "amount", "quantity", "product", "order"],
    "deeplink": ["url", "link", "address", "website", "redirect"],
    "storage":  ["path", "file", "dosya", "directory", "folder",
                 "location", "import", "export"],
}

SCREEN_CONTEXT_MAP = {
    "sql":      ["sql", "sqlite", "database", "db", "query", "search"],
    "xss":      ["xss", "script", "html", "inject", "webview", "display"],
    "auth":     ["login", "signin", "auth", "credential", "username", "password"],
    "api":      ["api", "url", "endpoint", "id", "account"],
    "deeplink": ["deeplink", "webview", "url", "link"],
    "storage":  ["storage", "file", "path", "directory"],
    "overflow": ["input", "validation", "name", "text", "enter"],
}

# payload gönderdikten sonraki gelen tepkilşer 
VULN_KEYWORDS = [
    "exception", "syntax error", "sql", "sqlite", "error",
    "stacktrace", "nullpointer", "fatal", "unauthorized",
    "forbidden", "root", "password", "token",
    "secret", "access denied", "overflow", "bypass",
]


def detect_field_type(resource_id: str, hint: str, label: str) -> list:
    """
    Input alanının türünü tespit eder.
    resource-id, hint metni ve yanındaki label'a bakarak
    hangi payload kategorisinin deneneceğine karar verir.
    """
    combined = (resource_id + " " + hint + " " + label).lower()
    matched  = []
    for ftype, keywords in FIELD_TYPE_MAP.items():
        if any(k in combined for k in keywords):
            matched.append(ftype)
    matched.append("overflow")  # her alana dene
    if matched == ["overflow"]:
        matched = ["sql", "xss", "auth", "overflow"]
    return matched


def detect_screen_type(screen_text: str) -> list:
    """Ekran genel metnine bakarak zafiyet türlerini belirle (fallback)."""
    text = screen_text.lower()
    matched = []
    for ptype, keywords in SCREEN_CONTEXT_MAP.items():
        if any(k in text for k in keywords):
            matched.append(ptype)
    if "overflow" not in matched:
        matched.append("overflow")
    if not matched or matched == ["overflow"]:
        matched = ["sql", "xss", "auth", "api", "overflow"]
    return matched


class UIAutomator:
    """

    Emülatördeki uygulamada:
    1. Menüde yukardan aşağıya gezinir
    2. Her ekrandaki input alanlarını bulur
    3. Ekran içeriğine göre uygun payload seçer
    4. Payload yazar, submit basar, yanıtı analiz eder
    5. Yeni gelen metinleri zafiyet olarak raporlar
    """

    def __init__(self, adb: ADBWrapper):
        self.adb      = adb
        self._stop    = Event()
        self._tested  = set()
        self.findings = []

    #ADB Yardımcıları

    def _dump(self, retries: int = 3) -> str:

        for attempt in range(retries):
            try:
                subprocess.run(
                    [self.adb.adb_path, "shell", "uiautomator", "dump", "/data/local/tmp/ui.xml"],
                    capture_output=True, timeout=10
                )
                r = subprocess.run(
                    [self.adb.adb_path, "shell", "cat", "/data/local/tmp/ui.xml"],
                    capture_output=True, text=True, timeout=5
                )
                xml = r.stdout
                # Geçerli XML mi? En az bir <node> içermeli
                if xml and "<node" in xml:
                    return xml
            except Exception:
                pass
            if attempt < retries - 1:
                time.sleep(0.8)
        return ""

    def _nodes(self, xml):
        try:    return list(ET.fromstring(xml).iter("node"))
        except: return []

    def _center(self, bounds):
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
        if m:
            x1, y1, x2, y2 = map(int, m.groups())
            return (x1 + x2) // 2, (y1 + y2) // 2
        return None

    def _tap(self, x, y, wait=0.2):
        subprocess.run([self.adb.adb_path, "shell", "input", "tap", str(x), str(y)],
                       capture_output=True)
        time.sleep(wait)

    def _type(self, text):
        import shlex
        # shlex.quote ile tüm özel karakterleri (< > ( ) ' " &) Android shell'inden korur
        escaped = shlex.quote(text.replace(" ", "%s"))
        subprocess.run(
            [self.adb.adb_path, "shell", f"input text {escaped}"],
            capture_output=True, timeout=10
        )
        time.sleep(0.15)

    def _clear(self, x, y):
        self._tap(x, y, wait=0.2)
        # Sona git, sonra 250 DEL — herhangi uzunluktaki payload'ı temizler (max ~200 kar)
        subprocess.run([self.adb.adb_path, "shell", "input", "keyevent", "KEYCODE_MOVE_END"],
                       capture_output=True)
        time.sleep(0.05)
        subprocess.run(
            [self.adb.adb_path, "shell", "input", "keyevent"] + ["67"] * 250,
            capture_output=True
        )
        time.sleep(0.1)

    def _dismiss_dialog(self) -> bool:
        """JS alert veya başka bir dialog açıksa tespit et ve kapat. True döner."""
        xml = self._dump()
        nodes = self._nodes(xml)
        texts = {n.attrib.get("text", "").strip() for n in nodes}
        is_dialog = "JavaScript" in texts or (
            any(n.attrib.get("text","") in ("OK","Cancel","Yes","No") and
                n.attrib.get("clickable") == "true"
                for n in nodes)
            and len(nodes) < 20  # dialog'lar az node içerir
        )
        if not is_dialog:
            return False
        # OK butonunu bul ve tıkla
        for n in nodes:
            if n.attrib.get("text","").strip() in ("OK", "Tamam") and n.attrib.get("clickable") == "true":
                c = self._center(n.attrib.get("bounds",""))
                if c:
                    self._tap(c[0], c[1], wait=0.4)
                    return True
        # OK bulunamazsa BACK ile kapat
        self._back()
        return True

    def _back(self):
        subprocess.run([self.adb.adb_path, "shell", "input", "keyevent", "KEYCODE_BACK"],
                       capture_output=True)
        time.sleep(0.6)

    def _screen_text(self, xml):
        return " ".join(
            n.attrib.get("text", "").lower()
            for n in self._nodes(xml) if n.attrib.get("text")
        )

    #  Fuzzing 

    def _fast_fuzz(self, inputs, buttons, payload, screen_types, baseline_texts: set):
        """Payload yaz, submit bas, baseline ile karşılaştır."""
        for i, (ix, iy, rid) in enumerate(inputs):
            self._clear(ix, iy)
            if i == 0:
                self._type(payload)
            else:
                self._type("test123" if "pass" in rid.lower() else "testuser")

        if buttons:
            self._tap(buttons[0][0], buttons[0][1], wait=0.8)
        else:
            subprocess.run([self.adb.adb_path, "shell", "input", "keyevent", "KEYCODE_ENTER"],
                           capture_output=True)
            time.sleep(0.8)

        after_xml   = self._dump()
        after_texts = {n.attrib.get("text", "").strip()
                       for n in self._nodes(after_xml)
                       if n.attrib.get("text", "").strip()}

        new_texts = after_texts - baseline_texts
        new_texts = {t for t in new_texts if len(t) > 3}
        vuln_hits = [t for t in new_texts if any(k in t.lower() for k in VULN_KEYWORDS)]

        if vuln_hits:
            msg = f"Payload: {payload!r} | Yeni ekran yaniti: {vuln_hits}"
            logger.critical(f"\033[91m  ZAFİYET! {msg}\033[0m")
            self.findings.append({
                "category":    "M7: Client Code Quality",
                "severity":    "CRITICAL",
                "title":       "Aktif Zafiyet Tespiti",
                "description": msg,
                "file":        inputs[0][2] if inputs else "unknown",
            })
            return True
        elif new_texts:
            logger.info(f"  → Yeni metin: {list(new_texts)[:2]}")

        after_inputs = [n for n in self._nodes(after_xml)
                        if "EditText" in n.attrib.get("class", "")]
        if not after_inputs:
            self._back()
        return False

    def _find_label_for_field(self, nodes, field_bounds: str) -> str:
        """
        Input alanının üzerindeki veya solundaki TextView'i bulur.
        Bu label, alanın ne olduğunu anlamak için kullanılır.
        Örnek: 'Username:' label'ı → auth payload seçimi.
        """
        fc = self._center(field_bounds)
        if not fc:
            return ""
        fx, fy = fc
        best_label = ""
        best_dist  = 999

        for n in nodes:
            if "TextView" not in n.attrib.get("class", ""):
                continue
            txt = n.attrib.get("text", "").strip()
            if not txt or len(txt) > 40:
                continue
            nc = self._center(n.attrib.get("bounds", ""))
            if not nc:
                continue
            nx, ny = nc
            # Alanın üstünde veya solunda, 200px içinde
            if (ny < fy) and abs(nx - fx) < 400 and (fy - ny) < 200:
                dist = fy - ny
                if dist < best_dist:
                    best_dist  = dist
                    best_label = txt

        return best_label

    def _fuzz_screen(self):
        xml = self._dump()
        if not xml:
            return

        sig = xml[50:200]
        if sig in self._tested:
            return
        self._tested.add(sig)

        ns      = self._nodes(xml)
        inputs  = []  # (x, y, resource_id, hint, label)
        buttons = []

        for n in ns:
            cls    = n.attrib.get("class", "")
            rid    = n.attrib.get("resource-id", "")
            bounds = n.attrib.get("bounds", "")
            hint   = n.attrib.get("text", "").strip()  # hint/placeholder
            c      = self._center(bounds)
            if not c:
                continue
            if "EditText" in cls:
                label = self._find_label_for_field(ns, bounds)
                inputs.append((c[0], c[1], rid, hint, label))
            elif n.attrib.get("clickable") == "true":
                txt = n.attrib.get("text", "").lower()
                if any(w in txt for w in ["login","submit","ok","enter","gir","display","ara","search"]):
                    buttons.append(c)

        if not inputs:
            logger.info("  Input alani yok.")
            return

        screen_txt = self._screen_text(xml)
        baseline_texts = {n.attrib.get("text","").strip()
                          for n in ns if n.attrib.get("text","").strip()}

        logger.info(f"  Ekran: {screen_txt[:60]!r}")
        logger.info(f"  {len(inputs)} input alani bulundu\n")

        for field_idx, (ix, iy, rid, hint, label) in enumerate(inputs):
            if self._stop.is_set():
                return

            # Her alan için ayrı tespit
            field_types = detect_field_type(rid, hint, label)
            logger.info(f"   Alan [{field_idx+1}]: rid={rid or 'adsiz'!r} "
                        f"hint={hint!r} label={label!r}")
            logger.info(f"     Tespit: {field_types}")

            # XSS her zaman önce, ardından alan türüne özel payloadlar
            priority = ["xss"] + [t for t in field_types if t != "xss"]
            payloads = list(dict.fromkeys(
                p for t in priority for p in PAYLOADS.get(t, [])
            ))
            logger.info(f"     {len(payloads)} payload denenecek\n")

            for payload in payloads:
                if self._stop.is_set():
                    return
                logger.info(f"   {payload!r}")

                # Sadece bu alana payload, diğerlerine uygun değer
                other_inputs = [
                    (ox, oy, orid, ohint, olabel)
                    for j, (ox, oy, orid, ohint, olabel) in enumerate(inputs)
                    if j != field_idx
                ]

                # Payload yaz
                self._clear(ix, iy)
                self._type(payload)

                # Diğer alanları doldur
                for ox, oy, orid, ohint, olabel in other_inputs:
                    self._clear(ox, oy)
                    if any(k in (orid+ohint+olabel).lower()
                           for k in ["pass","sifre","pwd"]):
                        self._type("test123")
                    else:
                        self._type("testuser")

                # Submit
                if buttons:
                    self._tap(buttons[0][0], buttons[0][1], wait=0.5)
                else:
                    subprocess.run([self.adb.adb_path,"shell","input",
                                    "keyevent","KEYCODE_ENTER"], capture_output=True)
                    time.sleep(0.5)

                #  Dialog tespiti (JS alert, confirm, prompt) 
                # Submit sonrası önce dialog kontrolü yap
                time.sleep(0.5)
                after_xml   = self._dump()
                after_nodes = self._nodes(after_xml)
                after_texts_raw = {n.attrib.get("text","").strip() for n in after_nodes}

                js_alert_fired = "JavaScript" in after_texts_raw

                if js_alert_fired:
                    detail = (f"Payload: {payload!r} | "
                              f"Alan: {rid or hint or label!r} | "
                              "WebView içinde JavaScript alert() tetiklendi.")
                    logger.critical(f"\033[91m  XSS ZAFİYETİ! {detail}\033[0m")
                    self.findings.append({
                        "category":    "M7: Client Code Quality",
                        "severity":    "CRITICAL",
                        "title":       "XSS — JavaScript Alert Tetiklendi",
                        "description": detail,
                        "file":        rid or hint or label,
                    })
                    # Dialog'u kapat, bir sonraki payload için hazırlan
                    self._dismiss_dialog()
                    time.sleep(0.5)
                    continue  # Bu alan için sonraki payload'a geç

                # Keyword tespiti (SQL bypass, auth bypass vb.)
                after_texts = {t for t in after_texts_raw if len(t) > 3}
                new_texts   = after_texts - {t for t in baseline_texts if len(t) > 3}
                # Payload metnini yansıyan metinlerden çıkar — false positive önleme
                payload_words = {w.lower() for w in payload.replace("<","").replace(">","").split() if len(w) > 3}
                filtered_new  = {t for t in new_texts
                                 if not any(w in t.lower() for w in payload_words)}

                vuln_hits = [t for t in filtered_new
                             if any(k in t.lower() for k in VULN_KEYWORDS)]

                if vuln_hits:
                    detail = (f"Payload: {payload!r} | "
                              f"Alan: {rid or hint or label!r} | "
                              f"Yeni yanit: {vuln_hits}")
                    logger.critical(f"\033[91mZAFİYET! {detail}\033[0m")
                    self.findings.append({
                        "category":    "M7: Client Code Quality",
                        "severity":    "CRITICAL",
                        "title":       f"Aktif Zafiyet — {field_types[0].upper()}",
                        "description": detail,
                        "file":        rid or hint or label,
                    })
                elif new_texts:
                    logger.info(f"  → Yeni metin: {list(new_texts)[:3]}")

                # Ekran değiştiyse (input kayboldu) geri dön
                after_inputs = [n for n in after_nodes if "EditText" in n.attrib.get("class","")]
                if not after_inputs:
                    self._back()
                    time.sleep(0.5)

        logger.info("  Ekran tamamlandi.")

    # Navigasyon

    def _menu_items(self, xml):
        skip  = {"back", "geri", "cancel", "iptal", "close", ""}
        items = [
            (self._center(n.attrib.get("bounds", ""))[1],
             self._center(n.attrib.get("bounds", "")),
             n.attrib.get("text", "").strip())
            for n in self._nodes(xml)
            if n.attrib.get("clickable") == "true"
            and n.attrib.get("text", "").strip().lower() not in skip
            and self._center(n.attrib.get("bounds", ""))
        ]
        items.sort()
        return [(c, t) for _, c, t in items]

    def _run_loop(self, duration: int, target_screen: str = None):
        logger.info(" Active Hacking basladı.")
        start, visited = time.time(), set()

        # Uygulama tam yüklenene kadar bekle (max 10 saniye)
        items = []
        for _ in range(10):
            time.sleep(1)
            xml   = self._dump()
            items = self._menu_items(xml)
            if items:
                break
            logger.info("  Uygulama yükleniyor, bekleniyor...")

        logger.info(f"  {len(items)} menu ogesi bulundu.")

        # Hiç menü öğesi bulunamazsa mevcut ekranı doğrudan tara
        if not items:
            logger.info("  Menü bulunamadı — mevcut ekranı doğrudan fuzzing ile tarıyorum...")
            self._fuzz_screen()

        if target_screen:
            logger.info(f"  Hedef ekran: {target_screen!r}")

        # Input alanı olan ekranları önce tara (login, xss, sql, flag içerenler)
        INPUT_PRIORITY = ["xss", "login", "sql", "flag one", "flag four", "flag six",
                          "flag seven", "flag ten", "unicode", "sqlite"]
        priority_items = [i for i in items
                          if any(k in i[1].lower() for k in INPUT_PRIORITY)]
        other_items    = [i for i in items
                          if not any(k in i[1].lower() for k in INPUT_PRIORITY)]
        items = priority_items + other_items

        for center_coord, text in items:
            if self._stop.is_set() or time.time() - start > duration:
                break
            if text in visited:
                continue

            # --screen verilmişse sadece o ekranı tara
            if target_screen and target_screen.upper() not in text.upper():
                logger.info(f"  Atlanıyor: {text!r}")
                continue

            logger.info(f"\n{'─'*50}")
            logger.info(f" → {text!r}")
            self._tap(center_coord[0], center_coord[1], wait=1.5)  # geçiş animasyonu için 1.5s
            visited.add(text)
            self._fuzz_screen()
            self._back()
            time.sleep(0.8)
            xml   = self._dump()
            items = self._menu_items(xml)
            # Öncelikli sıralamayı yeniden uygula
            priority_items = [i for i in items if i[1] not in visited
                              and any(k in i[1].lower() for k in INPUT_PRIORITY)]
            other_items    = [i for i in items if i[1] not in visited
                              and not any(k in i[1].lower() for k in INPUT_PRIORITY)]
            items = priority_items + other_items

        logger.info(f"\n{'='*55}")
        logger.info(f"TAMAMLANDI — {len(self.findings)} zafiyet")
        for i, f in enumerate(self.findings, 1):
            logger.critical(f"  [{i}] {f['description']}")
        logger.info(f"{'='*55}")

    def start(self, duration: int, target_screen: str = None):
        self._stop.clear()
        self._tested.clear()
        self.findings.clear()
        self._thread = Thread(
            target=self._run_loop,
            args=(duration,),
            kwargs={"target_screen": target_screen},
            daemon=True
        )
        self._thread.start()

    def watch(self, duration: int):
        """
        İzleme modu — sen gezin, bot input görünce devralır.
        Ekranda EditText belirdiği an payload enjekte eder.
        """
        self._stop.clear()
        self._tested.clear()
        self.findings.clear()
        self._thread = Thread(target=self._watch_loop, args=(duration,), daemon=True)
        self._thread.start()

    def _watch_loop(self, duration: int):
        logger.info("  İzleme modu — sen ekrana git, input görünce devralıyorum.")
        start    = time.time()
        last_sig = ""

        while not self._stop.is_set() and time.time() - start < duration:
            time.sleep(1.5)
            xml = self._dump()
            if not xml:
                continue

            ns     = self._nodes(xml)
            inputs = [(self._center(n.attrib.get("bounds","")),
                       n.attrib.get("resource-id",""),
                       n.attrib.get("text",""))
                      for n in ns if "EditText" in n.attrib.get("class","")
                      and self._center(n.attrib.get("bounds",""))]

            if not inputs:
                continue

            sig = xml[50:200]
            if sig == last_sig:
                continue
            last_sig = sig

            # İlk input alanını al
            center, rid, hint = inputs[0]
            ix, iy = center

            # Submit butonu
            buttons = []
            for n in ns:
                if n.attrib.get("clickable") == "true":
                    txt = n.attrib.get("text","").lower()
                    if any(w in txt for w in ["submit","login","ok","display","search","gir","ara"]):
                        c = self._center(n.attrib.get("bounds",""))
                        if c:
                            buttons.append(c)

            # Ekran baseline
            baseline = {n.attrib.get("text","").strip()
                        for n in ns if n.attrib.get("text","").strip()}

            # Ekran türüne göre payload seç
            screen_txt   = self._screen_text(xml)
            screen_types = detect_screen_type(screen_txt)
            field_types  = detect_field_type(rid, hint, "")
            # İkisini birleştir, tekrar yok
            combined_types = list(dict.fromkeys(field_types + screen_types))
            # XSS her zaman önce
            priority = ["xss"] + [t for t in combined_types if t != "xss"]
            payloads = list(dict.fromkeys(
                p for t in priority for p in PAYLOADS.get(t, [])
            ))

            logger.info(f"\nInput bulundu: {rid or hint!r}")
            logger.info(f"   Ekran türü: {combined_types}")
            logger.info(f"   {len(payloads)} payload tek tek denenecek\n")

            for payload in payloads:
                if self._stop.is_set():
                    break

                logger.info(f"  {payload!r}")

                # Temizle ve yaz
                self._clear(ix, iy)
                self._type(payload)

                # Diğer alanları doldur
                for other_c, orid, ohint in inputs[1:]:
                    self._clear(other_c[0], other_c[1])
                    if "pass" in (orid+ohint).lower():
                        self._type("test123")
                    else:
                        self._type("testuser")

                # Submit
                if buttons:
                    self._tap(buttons[0][0], buttons[0][1], wait=0.5)
                else:
                    subprocess.run([self.adb.adb_path,"shell","input","keyevent","KEYCODE_ENTER"],
                                   capture_output=True)
                    time.sleep(0.5)

                # Sonuç kontrol
                after_xml   = self._dump()
                after_texts = {n.attrib.get("text","").strip()
                               for n in self._nodes(after_xml)
                               if n.attrib.get("text","").strip()}
                new_texts   = {t for t in after_texts - baseline if len(t) > 3}
                vuln_hits   = [t for t in new_texts
                               if any(k in t.lower() for k in VULN_KEYWORDS)]

                if vuln_hits:
                    msg = f"Payload: {payload!r} → {vuln_hits}"
                    logger.critical(f"\033[91m  ZAFİYET! {msg}\033[0m")
                    self.findings.append({
                        "category":    "M7: Client Code Quality",
                        "severity":    "CRITICAL",
                        "title":       "Aktif Zafiyet Tespiti",
                        "description": msg,
                        "file":        rid or hint,
                    })
                elif new_texts:
                    logger.info(f"  → Yanıt: {list(new_texts)[:1]}")
                else:
                    logger.info(f"  → Reddedildi")

            logger.info("\n  Bitti. Sonraki ekrana geçebilirsin.")

        logger.info(f"\n{'='*55}")
        logger.info(f"İZLEME BITTI — {len(self.findings)} zafiyet")
        for i, f in enumerate(self.findings, 1):
            logger.critical(f"  [{i}] {f['description']}")
        logger.info(f"{'='*55}")

    def stop(self):
        self._stop.set()
        if hasattr(self, "_thread"):
            self._thread.join(timeout=3)
