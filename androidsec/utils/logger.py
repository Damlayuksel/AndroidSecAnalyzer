"""
Logging configuration for AndroidSecAnalyzer
Merkezi logging sistemi - Tüm loglar buradan yönetilir
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from androidsec.core.constants import LOGS_DIR


def setup_logger(
    name: str = "androidsec",
    level: str = "INFO",
    log_file: Optional[str] = None,
    console: bool = True
) -> logging.Logger:
    """
    Configure and return a logger instance
    
    Args:
        name: Logger adı (genellikle modül adı)
        level: Log seviyesi (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Log dosyası yolu (None ise sadece console)
        console: Console'a da log yazılsın mı?
    
    Returns:
        Yapılandırılmış logger instance
    
    Örnek kullanım:
        logger = setup_logger(__name__)
        logger.info("APK analizi başladı")
        logger.error("Hata oluştu", exc_info=True)

        2026-01-29 14:32:01 - androidsec - INFO - APK analizi başladı şeklinde çıktıyı verecek
 
    """
    # Logger oluştur
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Eğer handler zaten eklenmişse, tekrar ekleme (duplicate log önleme)
    if logger.handlers:
        return logger
    
    # Log formatı
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler (terminal'e yazdır)
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler (dosyaya yazdır)
    if log_file:
        # Log klasörünü oluştur
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger or create a new one
    Mevcut logger'ı al veya yeni oluştur
    
    Args:
        name: Logger adı
    
    Returns:
        Logger instance
    
    Örnek:
        logger = get_logger(__name__)
    """
    return logging.getLogger(name)


# Default logger instance (proje genelinde kullanılabilir)
default_logger = setup_logger(
    name="androidsec",
    level="INFO",
    log_file=f"{LOGS_DIR}/androidsec.log",
    console=True
)
