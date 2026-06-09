/**
 * Frida Crypto Hooks — Kriptografik işlemleri izler
 *
 * Uygulama çalışırken:
 * - Zayıf algoritmalar (MD5, SHA1, DES, RC4)
 * - ECB modu kullanımı
 * - Hardcoded key kullanımı
 * tespiti yapar.
 */

'use strict';

Java.perform(function () {

    // 
    // 1. MessageDigest (MD5 / SHA1 kullanımı)
    // 
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');

        MessageDigest.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            var algo = algorithm.toUpperCase();

            if (algo === 'MD5' || algo === 'SHA-1' || algo === 'SHA1') {
                send({
                    category: 'M5: Insufficient Cryptography',
                    severity: 'CRITICAL',
                    title: 'Zayıf hash algoritması kullanımı: ' + algo,
                    description: 'Uygulama çalışırken ' + algo + ' hash algoritması kullanıldığı tespit edildi.',
                    recommendation: 'SHA-256 veya SHA-3 kullanılmalıdır.'
                });
            }

            return this.getInstance(algorithm);
        };
    } catch (e) {
        // MessageDigest bulunamadı — sorun değil
    }

    // 
    // 2. Cipher (DES, RC4, ECB modu)
    // 
    try {
        var Cipher = Java.use('javax.crypto.Cipher');

        Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
            var t = transformation.toUpperCase();

            if (t.indexOf('DES') !== -1 && t.indexOf('TDES') === -1 && t.indexOf('3DES') === -1) {
                send({
                    category: 'M5: Insufficient Cryptography',
                    severity: 'CRITICAL',
                    title: 'Zayıf şifreleme algoritması: DES',
                    description: 'Uygulama DES algoritması kullanıyor: ' + transformation,
                    recommendation: 'AES-256 kullanılmalıdır.'
                });
            }

            if (t.indexOf('RC4') !== -1 || t.indexOf('ARCFOUR') !== -1) {
                send({
                    category: 'M5: Insufficient Cryptography',
                    severity: 'CRITICAL',
                    title: 'Zayıf şifreleme algoritması: RC4',
                    description: 'Uygulama RC4 algoritması kullanıyor: ' + transformation,
                    recommendation: 'AES-GCM kullanılmalıdır.'
                });
            }

            if (t.indexOf('ECB') !== -1) {
                send({
                    category: 'M5: Insufficient Cryptography',
                    severity: 'HIGH',
                    title: 'Güvensiz ECB modu kullanımı',
                    description: 'Uygulama ECB blok şifreleme modu kullanıyor: ' + transformation,
                    recommendation: 'CBC veya GCM modu kullanılmalıdır.'
                });
            }

            return this.getInstance(transformation);
        };
    } catch (e) {
        // Cipher bulunamadı
    }

    // ────────────────────────────────────────────
    // 3. SecretKeySpec (Hardcoded key tespiti)
    // ────────────────────────────────────────────
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');

        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algorithm) {
            var keyHex = '';
            for (var i = 0; i < keyBytes.length; i++) {
                var b = (keyBytes[i] & 0xff).toString(16);
                keyHex += (b.length === 1 ? '0' : '') + b;
            }

            send({
                category: 'M5: Insufficient Cryptography',
                severity: 'HIGH',
                title: 'SecretKeySpec ile anahtar oluşturma tespit edildi',
                description: 'Algoritma: ' + algorithm + ', Anahtar uzunluğu: ' + keyBytes.length + ' byte',
                recommendation: 'Anahtarlar Android Keystore kullanılarak yönetilmelidir.'
            });

            return this.$init(keyBytes, algorithm);
        };
    } catch (e) {
        // SecretKeySpec bulunamadı
    }

});
