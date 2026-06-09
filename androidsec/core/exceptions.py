"""
Custom exceptions for AndroidSecAnalyzer
Özel hata sınıfları - Her modül için spesifik hatalar
Hata olduğunda nerede oldugu kolayca anlaşılacak 
"""


class AndroidSecError(Exception):
    """
    Base exception for all AndroidSecAnalyzer errors
    Tüm hataların ana sınıfı
    """
    pass


class ConfigurationError(AndroidSecError):
    """
    Raised when there's a configuration error
    Konfigürasyon hatası olduğunda fırlatılır
    Örnek: YAML dosyası bulunamadı, geçersiz ayar
    """
    pass


class DecompilationError(AndroidSecError):
    """
    Raised when APK decompilation fails
    APK dekompilasyonu başarısız olduğunda
    Örnek: APKTool çalışmadı, bozuk APK dosyası
    """
    pass


class AnalysisError(AndroidSecError):
    """
    Raised when analysis fails
    Analiz başarısız olduğunda (genel hata)
    """
    pass


class StaticAnalysisError(AnalysisError):
    """
    Raised when static analysis fails
    Statik analiz hatası
    Örnek: Manifest parse edilemedi, kod taraması başarısız
    """
    pass


class DynamicAnalysisError(AnalysisError):
    """
    Raised when dynamic analysis fails
    Dinamik analiz hatası
    Örnek: Frida bağlanamadı, ADB çalışmıyor
    """
    pass


class DatabaseError(AndroidSecError):
    """
    Raised when database operations fail
    Veritabanı işlemi başarısız olduğunda
    Örnek: Bağlantı hatası, sorgu hatası
    """
    pass


class ReportGenerationError(AndroidSecError):
    """
    Raised when report generation fails
    Rapor oluşturma hatası
    Örnek: Template bulunamadı, HTML oluşturulamadı
    """
    pass


class ToolNotFoundError(AndroidSecError):
    """
    Raised when external tool is not found
    Harici araç bulunamadığında
    Örnek: APKTool yüklü değil, JADX bulunamadı
    """
    def __init__(self, tool_name: str, message: str = None):
        self.tool_name = tool_name
        if message is None:
            message = f"Required tool '{tool_name}' not found. Please install it first."
        super().__init__(message)


class InvalidAPKError(AndroidSecError):
    """
    Raised when APK file is invalid
    APK dosyası geçersiz olduğunda
    Örnek: Bozuk dosya, APK değil
    """
    pass


class DeviceNotFoundError(AndroidSecError):
    """
    Raised when Android device/emulator is not found
    Android cihaz veya emulator bulunamadığında
    """
    pass


class FridaError(DynamicAnalysisError):
    """
    Raised when Frida operations fail
    Frida işlemleri başarısız olduğunda
    Örnek: Frida server çalışmıyor, script hatası
    """
    pass


class ADBError(DynamicAnalysisError):
    """
    Raised when ADB operations fail
    ADB işlemleri başarısız olduğunda
    Örnek: Cihaz bağlı değil, komut başarısız
    """
    pass
