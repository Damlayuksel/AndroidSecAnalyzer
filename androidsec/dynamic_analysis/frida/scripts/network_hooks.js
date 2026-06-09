/**
 * Frida Network Hooks — Ağ trafiğini izler
 *
 * Uygulama çalışırken:
 * - HTTP bağlantıları (cleartext)
 * - SSL/TLS bypass girişimleri
 * - Certificate pinning bypass
 * tespiti yapar.
 */

'use strict';

Java.perform(function () {

    // 
    // 1. URL bağlantılarını izle (HTTP tespit)
    // 
    try {
        var URL = Java.use('java.net.URL');

        URL.$init.overload('java.lang.String').implementation = function (url) {
            if (url && url.toLowerCase().indexOf('http://') === 0) {
                send({
                    category: 'M3: Insecure Communication',
                    severity: 'HIGH',
                    title: 'Şifresiz HTTP bağlantısı tespit edildi',
                    description: 'Uygulama HTTP URL\'sine bağlanıyor: ' + url,
                    recommendation: 'Tüm bağlantılar HTTPS üzerinden yapılmalıdır.'
                });
            }

            return this.$init(url);
        };
    } catch (e) {
        // URL bulunamadı
    }

    // 
    // 2. TrustManager bypass tespiti
    // 
    try {
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

        // SSLContext.init ile custom TrustManager kullanımını izle
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (keyManagers, trustManagers, secureRandom) {

            if (trustManagers !== null) {
                send({
                    category: 'M3: Insecure Communication',
                    severity: 'HIGH',
                    title: 'Custom TrustManager ile SSLContext başlatıldı',
                    description: 'Uygulama özel TrustManager kullanıyor — sertifika doğrulaması bypass edilmiş olabilir.',
                    recommendation: 'Varsayılan TrustManager kullanılmalı veya certificate pinning uygulanmalıdır.'
                });
            }

            return this.init(keyManagers, trustManagers, secureRandom);
        };
    } catch (e) {
        // SSLContext bulunamadı
    }

    // 
    // 3. HostnameVerifier bypass tespiti
    // 
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');

        HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
            send({
                category: 'M3: Insecure Communication',
                severity: 'HIGH',
                title: 'Custom HostnameVerifier ayarlandı',
                description: 'Uygulama HostnameVerifier\'ı override ediyor — hostname doğrulaması devre dışı bırakılmış olabilir.',
                recommendation: 'Varsayılan HostnameVerifier kullanılmalıdır.'
            });

            return this.setHostnameVerifier(verifier);
        };
    } catch (e) {
        // HttpsURLConnection bulunamadı
    }

    // 
    // 4. WebView SSL hatası bypass tespiti
    // 
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');

        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            send({
                category: 'M3: Insecure Communication',
                severity: 'CRITICAL',
                title: 'WebView SSL hatası bypass edildi',
                description: 'Uygulama WebView\'da SSL hatasını görmezden geliyor — MITM saldırılarına açık.',
                recommendation: 'onReceivedSslError içinde handler.cancel() çağrılmalıdır.'
            });

            return this.onReceivedSslError(view, handler, error);
        };
    } catch (e) {
        // WebViewClient bulunamadı
    }

});
