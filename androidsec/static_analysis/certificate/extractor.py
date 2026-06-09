"""
Certificate Extractor
APK'dan sertifika (imza) bilgilerini çıkarır

APK Sertifikası nerede?
- APK aslında bir ZIP dosyası
- İçinde META-INF/ klasörü var
- META-INF/CERT.RSA veya CERT.DSA → Sertifika dosyası

Ne çıkarıyoruz?
- İmzalayan kişi/şirket (CN - Common Name)
- Organizasyon (O - Organization)
- Geçerlilik tarihleri (başlangıç, bitiş)
- Sertifika tipi (RSA, DSA, EC)
- Parmak izi (fingerprint - SHA256)
"""

import re
import zipfile
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import subprocess
import tempfile

from androidsec.core.exceptions import StaticAnalysisError
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class CertificateExtractor:
    """
    APK sertifikasını çıkarır ve bilgilerini parse eder
    
    Kullanım:
        extractor = CertificateExtractor()
        cert_info = extractor.extract("app.apk")
        
        print(cert_info["subject"])  # "CN=MyCompany"
        print(cert_info["valid_from"])  # "2023-01-01"
    """
    
    def __init__(self):
        """Initialize certificate extractor"""
        logger.debug("CertificateExtractor initialized")
    
    def extract(self, apk_path: str) -> Dict[str, Any]:
        """
        APK'dan sertifika bilgilerini çıkar
        
        Args:
            apk_path: APK dosyası yolu
        
        Returns:
            Sertifika bilgileri: {
                "subject": "CN=MyCompany, O=MyOrg",
                "issuer": "CN=MyCompany, O=MyOrg",
                "valid_from": "2023-01-01 00:00:00",
                "valid_to": "2053-01-01 00:00:00",
                "serial_number": "1234567890",
                "signature_algorithm": "SHA256withRSA",
                "version": 3,
                "fingerprint_sha256": "AB:CD:EF:...",
            }
        
        Raises:
            StaticAnalysisError: Sertifika çıkarılamazsa
        """
        logger.info(f"Extracting certificate from: {apk_path}")
        
        try:
            # 1. APK'dan sertifika dosyasını bul
            cert_file = self._find_certificate_file(apk_path)
            
            if not cert_file:
                raise StaticAnalysisError("Certificate file not found in APK")
            
            # 2. Sertifika bilgilerini parse et
            cert_info = self._parse_certificate(apk_path, cert_file)
            
            logger.info(f"Certificate extracted: {cert_info.get('subject', 'Unknown')}")
            return cert_info
            
        except Exception as e:
            error_msg = f"Failed to extract certificate: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise StaticAnalysisError(error_msg) from e
    
    def _find_certificate_file(self, apk_path: str) -> Optional[str]:
        """
        APK içinde sertifika dosyasını bul
        
        APK bir ZIP dosyası, içinde META-INF/ klasörü var:
        - META-INF/CERT.RSA  (RSA sertifikası)
        - META-INF/CERT.DSA  (DSA sertifikası)
        - META-INF/CERT.EC   (EC sertifikası)
        
        Returns:
            Sertifika dosyası adı (örn: "META-INF/CERT.RSA")
        """
        logger.debug(f"Looking for certificate in: {apk_path}")
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # APK içindeki tüm dosyaları listele
                file_list = apk_zip.namelist()
                
                # Sertifika dosyalarını ara
                cert_extensions = ['.RSA', '.DSA', '.EC']
                
                for file_name in file_list:
                    # META-INF/ klasöründe mi?
                    if file_name.startswith('META-INF/'):
                        # Sertifika uzantısı var mı?
                        for ext in cert_extensions:
                            if file_name.upper().endswith(ext):
                                logger.debug(f"Found certificate: {file_name}")
                                return file_name
                
                logger.warning("No certificate file found in META-INF/")
                return None
                
        except zipfile.BadZipFile:
            raise StaticAnalysisError(f"Invalid APK file: {apk_path}")
        except Exception as e:
            raise StaticAnalysisError(f"Failed to read APK: {e}")
    
    def _parse_certificate(self, apk_path: str, cert_file: str) -> Dict[str, Any]:
        """
        Sertifika dosyasını parse et

        Önce keytool ile dener, başarısız olursa manual parse yapar.

        Args:
            apk_path: APK dosyası yolu
            cert_file: Sertifika dosyası adı (META-INF/CERT.RSA)

        Returns:
            Sertifika bilgileri dictionary
        """
        logger.debug(f"Parsing certificate: {cert_file}")

        # Önce keytool ile dene
        cert_info = self._parse_with_keytool(apk_path, cert_file)

        if cert_info:
            return cert_info

        # keytool yoksa manual parse dene
        logger.info("keytool not available, using manual parsing")
        return self._parse_manually(apk_path, cert_file)

    def _parse_with_keytool(self, apk_path: str, cert_file: str) -> Optional[Dict[str, Any]]:
        """
        Java keytool kullanarak sertifika bilgilerini çıkar

        keytool -printcert -jarfile app.apk komutu ile
        APK'nın sertifika bilgilerini alır.

        Args:
            apk_path: APK dosyası yolu
            cert_file: Sertifika dosya adı

        Returns:
            Sertifika bilgileri veya None (keytool yoksa)
        """
        import hashlib

        # Önce sertifika verisini APK'dan çıkar ve geçici dosyaya yaz
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                cert_data = apk_zip.read(cert_file)
        except Exception as e:
            logger.warning(f"Failed to extract certificate from APK: {e}")
            return None

        # Geçici dosyaya yaz
        with tempfile.NamedTemporaryFile(suffix='.RSA', delete=False) as tmp:
            tmp.write(cert_data)
            tmp_path = tmp.name

        try:
            # keytool -printcert -file cert.RSA
            result = subprocess.run(
                ['keytool', '-printcert', '-file', tmp_path],
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode != 0:
                logger.debug(f"keytool failed: {result.stderr}")
                return None

            output = result.stdout

            # keytool çıktısını parse et
            cert_info = {
                "cert_file": cert_file,
                "raw_output": output[:3000],
            }

            # Owner (Subject) bilgisi
            owner_match = re.search(r'Owner:\s*(.+)', output)
            if owner_match:
                cert_info["subject"] = owner_match.group(1).strip()

            # Issuer bilgisi
            issuer_match = re.search(r'Issuer:\s*(.+)', output)
            if issuer_match:
                cert_info["issuer"] = issuer_match.group(1).strip()

            # Serial Number
            serial_match = re.search(r'Serial number:\s*(\S+)', output)
            if serial_match:
                cert_info["serial_number"] = serial_match.group(1).strip()

            # Valid from ... until ...
            valid_match = re.search(
                r'Valid from:\s*(.+?)\s+until:\s*(.+)',
                output
            )
            if valid_match:
                cert_info["valid_from"] = self._parse_keytool_date(valid_match.group(1))
                cert_info["valid_to"] = self._parse_keytool_date(valid_match.group(2))

            # Signature algorithm
            algo_match = re.search(r'Signature algorithm name:\s*(\S+)', output)
            if algo_match:
                cert_info["signature_algorithm"] = algo_match.group(1).strip()

            # Version
            version_match = re.search(r'Version:\s*(\d+)', output)
            if version_match:
                cert_info["version"] = int(version_match.group(1))

            # SHA256 fingerprint
            sha256_match = re.search(r'SHA256:\s*(\S+)', output)
            if sha256_match:
                cert_info["fingerprint_sha256"] = sha256_match.group(1).strip()

            # SHA1 fingerprint
            sha1_match = re.search(r'SHA1:\s*(\S+)', output)
            if sha1_match:
                cert_info["fingerprint_sha1"] = sha1_match.group(1).strip()

            # MD5 fingerprint
            md5_match = re.search(r'MD5:\s*(\S+)', output)
            if md5_match:
                cert_info["fingerprint_md5"] = md5_match.group(1).strip()

            # Subject'ten CN ve O bilgilerini çıkar
            subject = cert_info.get("subject", "")
            cn_match = re.search(r'CN=([^,]+)', subject)
            if cn_match:
                cert_info["common_name"] = cn_match.group(1).strip()

            org_match = re.search(r'O=([^,]+)', subject)
            if org_match:
                cert_info["organization"] = org_match.group(1).strip()

            # Eksik alanları varsayılan değerlerle doldur
            cert_info.setdefault("subject", "CN=Unknown")
            cert_info.setdefault("issuer", "CN=Unknown")
            cert_info.setdefault("valid_from", "Unknown")
            cert_info.setdefault("valid_to", "Unknown")
            cert_info.setdefault("serial_number", "Unknown")
            cert_info.setdefault("signature_algorithm", "Unknown")
            cert_info.setdefault("version", 0)
            cert_info.setdefault("fingerprint_sha256", "Unknown")

            logger.info(f"Certificate parsed with keytool: {cert_info.get('subject')}")
            return cert_info

        except FileNotFoundError:
            logger.debug("keytool not found in PATH")
            return None
        except subprocess.TimeoutExpired:
            logger.warning("keytool command timed out")
            return None
        except Exception as e:
            logger.warning(f"keytool parsing failed: {e}")
            return None
        finally:
            # Geçici dosyayı sil
            import os
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _parse_manually(self, apk_path: str, cert_file: str) -> Dict[str, Any]:
        """
        Sertifikayı keytool olmadan parse et

        DER formatındaki sertifika verisinden temel bilgileri çıkarır.
        Hash fingerprint'lerini hesaplar.

        Args:
            apk_path: APK dosyası yolu
            cert_file: Sertifika dosya adı

        Returns:
            Sertifika bilgileri dictionary
        """
        import hashlib

        cert_info = {
            "cert_file": cert_file,
            "subject": "CN=Unknown, O=Unknown",
            "issuer": "CN=Unknown, O=Unknown",
            "valid_from": "Unknown",
            "valid_to": "Unknown",
            "serial_number": "Unknown",
            "signature_algorithm": "Unknown",
            "version": 0,
            "fingerprint_sha256": "Unknown",
            "fingerprint_sha1": "Unknown",
            "fingerprint_md5": "Unknown",
        }

        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                cert_data = apk_zip.read(cert_file)

            # Sertifika verisinin hash'lerini hesapla
            # Not: Bu, PKCS#7 container'ın hash'i, saf X.509 sertifikanın değil.
            # Tam doğruluk için cryptography kütüphanesi gerekir.
            sha256_hash = hashlib.sha256(cert_data).hexdigest().upper()
            sha1_hash = hashlib.sha1(cert_data).hexdigest().upper()
            md5_hash = hashlib.md5(cert_data).hexdigest().upper()

            # Hash'leri : ile ayırarak formatlama (AB:CD:EF:...)
            cert_info["fingerprint_sha256"] = ':'.join(
                sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2)
            )
            cert_info["fingerprint_sha1"] = ':'.join(
                sha1_hash[i:i+2] for i in range(0, len(sha1_hash), 2)
            )
            cert_info["fingerprint_md5"] = ':'.join(
                md5_hash[i:i+2] for i in range(0, len(md5_hash), 2)
            )

            # DER/PKCS#7 verisinden temel string bilgileri çıkarmaya çalış
            self._extract_strings_from_der(cert_data, cert_info)

            # Sertifika boyutu
            cert_info["cert_size"] = len(cert_data)

            logger.info(f"Certificate parsed manually: {cert_info.get('subject')}")

        except Exception as e:
            logger.warning(f"Manual certificate parsing failed: {e}")

        return cert_info

    def _extract_strings_from_der(self, data: bytes, cert_info: Dict[str, Any]) -> None:
        """
        DER/PKCS#7 verisinden okunabilir stringleri çıkar

        Sertifika verisinde CN=, O=, OU= gibi bilgiler
        genellikle UTF-8/ASCII olarak saklanır.

        Args:
            data: Ham sertifika verisi
            cert_info: Sonuçların yazılacağı dictionary
        """
        import re as regex

        # Binary'den okunabilir stringleri çıkar
        text = data.decode('latin-1', errors='ignore')

        # Common Name (CN) aramak
        cn_matches = regex.findall(r'CN=([^,\x00-\x1f]+)', text)
        if cn_matches:
            # İlk CN → subject, ikinci CN → issuer (genellikle)
            cert_info["common_name"] = cn_matches[0].strip()
            cert_info["subject"] = f"CN={cn_matches[0].strip()}"
            if len(cn_matches) > 1:
                cert_info["issuer"] = f"CN={cn_matches[1].strip()}"
            else:
                cert_info["issuer"] = cert_info["subject"]

        # Organization (O)
        o_matches = regex.findall(r'(?<![A-Z])O=([^,\x00-\x1f]+)', text)
        if o_matches:
            cert_info["organization"] = o_matches[0].strip()
            cert_info["subject"] += f", O={o_matches[0].strip()}"

        # Organizational Unit (OU)
        ou_matches = regex.findall(r'OU=([^,\x00-\x1f]+)', text)
        if ou_matches:
            cert_info["organizational_unit"] = ou_matches[0].strip()

        # Country (C)
        c_matches = regex.findall(r'(?<![A-Z])C=([A-Z]{2})', text)
        if c_matches:
            cert_info["country"] = c_matches[0]

        # Locality (L) ve State (ST)
        l_matches = regex.findall(r'(?<![A-Z])L=([^,\x00-\x1f]+)', text)
        if l_matches:
            cert_info["locality"] = l_matches[0].strip()

        st_matches = regex.findall(r'ST=([^,\x00-\x1f]+)', text)
        if st_matches:
            cert_info["state"] = st_matches[0].strip()

        # Signature Algorithm
        algo_indicators = {
            b'sha256WithRSAEncryption': 'SHA256withRSA',
            b'sha1WithRSAEncryption': 'SHA1withRSA',
            b'md5WithRSAEncryption': 'MD5withRSA',
            b'sha384WithRSAEncryption': 'SHA384withRSA',
            b'sha512WithRSAEncryption': 'SHA512withRSA',
            b'ecdsa-with-SHA256': 'SHA256withECDSA',
            b'dsa-with-SHA256': 'SHA256withDSA',
        }

        for indicator, algo_name in algo_indicators.items():
            if indicator in data:
                cert_info["signature_algorithm"] = algo_name
                break

    def _parse_keytool_date(self, date_str: str) -> str:
        """
        keytool tarih formatını standart formata çevir

        Girdi örnekleri:
        - "Mon Jan 01 00:00:00 UTC 2023"
        - "Sat Dec 31 23:59:59 TRT 2053"

        Çıktı: "2023-01-01 00:00:00"
        """
        try:
            # Birden fazla tarih formatını dene
            for fmt in [
                "%a %b %d %H:%M:%S %Z %Y",  # Mon Jan 01 00:00:00 UTC 2023
                "%Y-%m-%d %H:%M:%S",          # 2023-01-01 00:00:00
                "%b %d, %Y",                  # Jan 01, 2023
            ]:
                try:
                    dt = datetime.strptime(date_str.strip(), fmt)
                    return dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue

            # Hiçbiri uymadıysa orijinal stringi döndür
            return date_str.strip()

        except Exception:
            return date_str.strip()

    def get_fingerprint(self, apk_path: str, algorithm: str = "SHA256") -> str:
        """
        Sertifika parmak izini (fingerprint) al

        Fingerprint nedir?
        - Sertifikanın benzersiz kimliği
        - Hash algoritması ile hesaplanır (MD5, SHA1, SHA256)
        - Örnek: "AB:CD:EF:12:34:56:..."

        Args:
            apk_path: APK dosyası yolu
            algorithm: Hash algoritması (MD5, SHA1, SHA256)

        Returns:
            Fingerprint string (örn: "AB:CD:EF:...")
        """
        logger.debug(f"Getting {algorithm} fingerprint")

        cert_info = self.extract(apk_path)

        fingerprint_key = f"fingerprint_{algorithm.lower()}"
        return cert_info.get(fingerprint_key, "Unknown")

    def __repr__(self) -> str:
        return "CertificateExtractor()"
