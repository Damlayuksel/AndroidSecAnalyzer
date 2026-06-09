"""
androidsec/dynamic_analysis/collectors/storage.py

Logcat içinden veri saklama ile ilgili basit güvenlik bulgularını çıkarır.
"""

import logging
import re

logger = logging.getLogger(__name__)


class StorageCollector:
    def __init__(self):
        self.patterns = [
            # Hassas veri loglama — değer içermeli
            (r"password[=:\s]+\S+",
             "Parola değeri loglanıyor", "HIGH",
             "M2: Insecure Data Storage",
             "Parola değeri loglanıyor. Hassas veriler asla loglanmamalıdır."),
            (r"(auth|access|bearer|refresh|session)[\s_-]*token[=:\s]+\S+",
             "Auth token değeri loglanıyor", "HIGH",
             "M2: Insecure Data Storage",
             "Kimlik doğrulama token'ı loglanıyor. Token'lar güvenli depolanmalıdır."),
            (r"api[_-]?key[=:\s]+\S{8,}",
             "API anahtarı loglanıyor", "HIGH",
             "M9: Reverse Engineering",
             "API anahtarı loglarda tespit edildi."),
            (r"private[_-]?key[=:\s]|-----begin.*private",
             "Private key loglanıyor", "HIGH",
             "M5: Insufficient Cryptography",
             "Özel anahtar loglarda tespit edildi."),
            (r"(execsql|rawquery|insert into|select.*from).*\(",
             "SQL sorgusu loglanıyor", "MEDIUM",
             "M2: Insecure Data Storage",
             "SQL sorgusu loglanıyor. Hassas sorgu detayları loglanmamalıdır."),
            (r"mode_world_readable|mode_world_writable|openfileoutput.*0x1|0x3\)",
             "Herkese açık dosya modu kullanılıyor", "HIGH",
             "M2: Insecure Data Storage",
             "World-readable/writable dosya modu tespit edildi."),
            (r"getexternalstoragepublicdirectory|environment\.getexternal",
             "Harici depolama erişimi", "MEDIUM",
             "M2: Insecure Data Storage",
             "Harici depolama erişimi tespit edildi."),
            (r"<script[\s>]|javascript:|onerror=|onload=",
             "XSS payload loglanıyor", "HIGH",
             "M7: Client Code Quality",
             "XSS payload'u loglara yansıdı. Input validation eksik."),
            (r"' or '1'='1|or 1=1|union select|drop table",
             "SQL injection payload loglanıyor", "HIGH",
             "M7: Client Code Quality",
             "SQL injection payload'u loglara yansıdı. Input validation eksik."),
            (r"(username|user|login)[=:\s]+\w+.*(password|pass|pwd)[=:\s]+\S+",
             "Kullanıcı adı ve parola birlikte loglanıyor", "HIGH",
             "M2: Insecure Data Storage",
             "Kimlik bilgileri loglanıyor. Hassas veriler asla loglanmamalıdır."),
        ]

    def analyze(self, logs):
        if not logs:
            logger.warning("Analiz edilecek log bulunamadı.")
            return []

        findings = []
        seen = set()

        lines = logs.splitlines()

        for line in lines:
            line_lower = line.lower()

            for pattern, title, severity, category, recommendation in self.patterns:
                if re.search(pattern, line_lower):
                    key = title

                    if key not in seen:
                        seen.add(key)

                        findings.append({
                            "category": category,
                            "severity": severity,
                            "title": title,
                            "description": f"Logcat'te en az bir kere tespit edildi: {line.strip()[:200]}",
                            "detail": line.strip(),
                            "recommendation": recommendation,
                        })

        logger.info("Storage analizi tamamlandı. Bulgu sayısı: %d", len(findings))
        return findings

    def summarize(self, findings):
        summary = {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        summary["total"] = len(findings)

        for finding in findings:
            severity = finding["severity"]

            if severity == "HIGH":
                summary["high"] += 1
            elif severity == "MEDIUM":
                summary["medium"] += 1
            elif severity == "LOW":
                summary["low"] += 1

        return summary
