"""
Test Configuration
Pytest yapılandırması ve paylaşılan fixture'lar
"""

import sys
from pathlib import Path

import pytest

# Proje kök dizinini Python path'ine ekle
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixtures.mock_data import (
    create_test_manifest_file,
    create_test_apk,
    create_test_decompiled_dir,
    cleanup_test_file,
    cleanup_test_dir,
    SAMPLE_MANIFEST_SECURE,
    SAMPLE_MANIFEST_VULNERABLE,
    SAMPLE_MANIFEST_MINIMAL,
    SAMPLE_CERT_INFO_NORMAL,
    SAMPLE_CERT_INFO_EXPIRED,
    SAMPLE_CERT_INFO_DEBUG,
    SAMPLE_CERT_INFO_WEAK_ALGO,
    SAMPLE_CERT_INFO_SHORT_VALIDITY,
)


# Manifest Fixture'ları

@pytest.fixture
def vulnerable_manifest_file():
    """Zafiyetli AndroidManifest.xml dosyası"""
    path = create_test_manifest_file(SAMPLE_MANIFEST_VULNERABLE)
    yield path
    cleanup_test_file(path)


@pytest.fixture
def secure_manifest_file():
    """Güvenli AndroidManifest.xml dosyası"""
    path = create_test_manifest_file(SAMPLE_MANIFEST_SECURE)
    yield path
    cleanup_test_file(path)


@pytest.fixture
def minimal_manifest_file():
    """Minimal AndroidManifest.xml dosyası"""
    path = create_test_manifest_file(SAMPLE_MANIFEST_MINIMAL)
    yield path
    cleanup_test_file(path)


# APK Fixture'ları

@pytest.fixture
def vulnerable_apk():
    """Zafiyetli APK dosyası"""
    path = create_test_apk(
        manifest_content=SAMPLE_MANIFEST_VULNERABLE,
        include_cert=True,
        include_so=True,
    )
    yield path
    cleanup_test_file(path)


@pytest.fixture
def secure_apk():
    """Güvenli APK dosyası"""
    path = create_test_apk(
        manifest_content=SAMPLE_MANIFEST_SECURE,
        include_cert=True,
        include_so=False,
    )
    yield path
    cleanup_test_file(path)


@pytest.fixture
def minimal_apk():
    """Minimal APK dosyası"""
    path = create_test_apk(
        manifest_content=SAMPLE_MANIFEST_MINIMAL,
        include_cert=True,
        include_so=False,
    )
    yield path
    cleanup_test_file(path)


# Decompiled Dir Fixture'ları

@pytest.fixture
def vulnerable_decompiled_dir():
    """Zafiyetli dekompile edilmiş klasör"""
    path = create_test_decompiled_dir(
        manifest_content=SAMPLE_MANIFEST_VULNERABLE,
        include_so=True,
    )
    yield path
    cleanup_test_dir(path)


@pytest.fixture
def secure_decompiled_dir():
    """Güvenli dekompile edilmiş klasör (güvenli Java kodu ile)"""
    from tests.fixtures.mock_data import SAMPLE_JAVA_SECURE
    path = create_test_decompiled_dir(
        manifest_content=SAMPLE_MANIFEST_SECURE,
        java_files={
            "smali/com/example/secureapp/SecureActivity.java": SAMPLE_JAVA_SECURE,
        },
        include_so=False,
    )
    yield path
    cleanup_test_dir(path)


# Sertifika Fixture'ları

@pytest.fixture
def normal_cert_info():
    """Normal sertifika bilgileri"""
    return SAMPLE_CERT_INFO_NORMAL.copy()


@pytest.fixture
def expired_cert_info():
    """Süresi dolmuş sertifika bilgileri"""
    return SAMPLE_CERT_INFO_EXPIRED.copy()


@pytest.fixture
def debug_cert_info():
    """Debug sertifika bilgileri"""
    return SAMPLE_CERT_INFO_DEBUG.copy()


@pytest.fixture
def weak_algo_cert_info():
    """Zayıf algoritmalı sertifika bilgileri"""
    return SAMPLE_CERT_INFO_WEAK_ALGO.copy()


@pytest.fixture
def short_validity_cert_info():
    """Kısa geçerliliğe sahip sertifika bilgileri"""
    return SAMPLE_CERT_INFO_SHORT_VALIDITY.copy()
