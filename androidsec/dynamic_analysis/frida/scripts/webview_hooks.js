/**
 * Frida WebView Hooks — XSS ve WebView güvenlik açıklarını izler
 *
 * Hook edilen metodlar:
 * 1. WebView.loadData()         — kullanıcı girdisi HTML olarak yükleniyorsa XSS
 * 2. WebView.loadUrl()          — javascript: şeması ile XSS
 * 3. WebView.loadDataWithBaseURL() — HTML içerik yükleme
 * 4. WebSettings.setJavaScriptEnabled() — JS etkinleştirme
 * 5. WebSettings.setAllowFileAccess()   — dosya erişimi
 * 6. WebSettings.setAllowUniversalAccessFromFileURLs() — CORS bypass
 * 7. WebView.addJavascriptInterface() — JS bridge injection
 */

'use strict';

Java.perform(function () {

    //  XSS Keyword tespiti 
    function containsXSSPayload(str) {
        if (!str) return false;
        var lower = str.toLowerCase();
        var patterns = [
            '<script', 'javascript:', 'onerror=', 'onload=',
            'onclick=', 'alert(', 'prompt(', 'confirm(',
            'document.cookie', 'document.write', 'eval(',
            'svg/onload', 'img src=x', '"><', "'><",
        ];
        for (var i = 0; i < patterns.length; i++) {
            if (lower.indexOf(patterns[i]) !== -1) return true;
        }
        return false;
    }

    // 1. WebView.loadData() — HTML olarak kullanıcı girdisi 
    try {
        var WebView = Java.use('android.webkit.WebView');

        WebView.loadData.implementation = function (data, mimeType, encoding) {
            if (data && containsXSSPayload(data)) {
                send({
                    category: 'M7: Client Code Quality',
                    severity: 'CRITICAL',
                    title: 'XSS: loadData() ile XSS Payload Tespit Edildi',
                    description: 'WebView.loadData() çağrısında XSS payload bulundu. ' +
                                 'İçerik: ' + data.substring(0, 200),
                    recommendation: 'Kullanıcı girdisi HTML encode edilmeli, JavaScript devre dışı bırakılmalı.'
                });
            } else if (mimeType && mimeType.indexOf('html') !== -1) {
                send({
                    category: 'M7: Client Code Quality',
                    severity: 'HIGH',
                    title: 'XSS Riski: loadData() HTML İçerik Yüklüyor',
                    description: 'WebView.loadData() ile HTML içerik yükleniyor. ' +
                                 'Kullanıcı girdisi içeriyorsa XSS zafiyeti oluşabilir. MimeType: ' + mimeType,
                    recommendation: 'Kullanıcı girdisini doğrulayın ve encode edin.'
                });
            }
            return this.loadData(data, mimeType, encoding);
        };
    } catch (e) { /* WebView yok */ }

    // 2. WebView.loadUrl() — javascript: şeması 
    try {
        var WebView2 = Java.use('android.webkit.WebView');

        WebView2.loadUrl.overload('java.lang.String').implementation = function (url) {
            if (url) {
                if (url.toLowerCase().indexOf('javascript:') === 0) {
                    send({
                        category: 'M7: Client Code Quality',
                        severity: 'CRITICAL',
                        title: 'XSS: loadUrl() javascript: Şeması Kullanıyor',
                        description: 'WebView.loadUrl() javascript: şemasıyla çağrıldı. ' +
                                     'URL: ' + url.substring(0, 200),
                        recommendation: 'javascript: şemasına izin verilmemeli, URL whitelist uygulanmalı.'
                    });
                } else if (url.toLowerCase().indexOf('file://') === 0) {
                    send({
                        category: 'M6: Insecure Authorization',
                        severity: 'HIGH',
                        title: 'WebView file:// Protokolü Kullanıyor',
                        description: 'WebView file:// protokolüyle yerel dosya yüklüyor. ' +
                                     'URL: ' + url.substring(0, 200),
                        recommendation: 'file:// protokolüne erişimi kısıtlayın.'
                    });
                }
            }
            return this.loadUrl(url);
        };
    } catch (e) { /* WebView yok */ }

    //  3. WebView.loadDataWithBaseURL() 
    try {
        var WebView3 = Java.use('android.webkit.WebView');

        WebView3.loadDataWithBaseURL.implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
            if (data && containsXSSPayload(data)) {
                send({
                    category: 'M7: Client Code Quality',
                    severity: 'CRITICAL',
                    title: 'XSS: loadDataWithBaseURL() XSS Payload Tespit Edildi',
                    description: 'loadDataWithBaseURL() içinde XSS payload bulundu. ' +
                                 'BaseURL: ' + baseUrl + ' | İçerik: ' + data.substring(0, 150),
                    recommendation: 'Kullanıcı girdisi HTML encode edilmeli.'
                });
            }
            return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        };
    } catch (e) { /* WebView yok */ }

    //  4. WebSettings.setJavaScriptEnabled() 
    try {
        var WebSettings = Java.use('android.webkit.WebSettings');

        WebSettings.setJavaScriptEnabled.implementation = function (flag) {
            if (flag === true) {
                send({
                    category: 'M1: Improper Platform Usage',
                    severity: 'HIGH',
                    title: 'WebView JavaScript Runtime\'da Etkinleştirildi',
                    description: 'setJavaScriptEnabled(true) çağrıldı. ' +
                                 'Güvenilmeyen içerik yüklenirse XSS saldırısına açık.',
                    recommendation: 'JavaScript sadece zorunluysa etkinleştirilmeli.'
                });
            }
            return this.setJavaScriptEnabled(flag);
        };
    } catch (e) { /* WebSettings yok */ }

    // 5. WebSettings.setAllowFileAccess()
    try {
        var WebSettings2 = Java.use('android.webkit.WebSettings');

        WebSettings2.setAllowFileAccess.implementation = function (allow) {
            if (allow === true) {
                send({
                    category: 'M2: Insecure Data Storage',
                    severity: 'HIGH',
                    title: 'WebView Dosya Erişimine İzin Veriyor',
                    description: 'setAllowFileAccess(true) çağrıldı. ' +
                                 'Saldırgan file:// ile yerel dosyalara erişebilir.',
                    recommendation: 'setAllowFileAccess(false) olarak ayarlayın.'
                });
            }
            return this.setAllowFileAccess(allow);
        };
    } catch (e) { /* WebSettings yok */ }

    //  6. WebSettings.setAllowUniversalAccessFromFileURLs() 
    try {
        var WebSettings3 = Java.use('android.webkit.WebSettings');

        WebSettings3.setAllowUniversalAccessFromFileURLs.implementation = function (flag) {
            if (flag === true) {
                send({
                    category: 'M1: Improper Platform Usage',
                    severity: 'CRITICAL',
                    title: 'WebView Universal File Access Etkin — CORS Bypass',
                    description: 'setAllowUniversalAccessFromFileURLs(true) çağrıldı. ' +
                                 'file:// URL\'lerinden her kaynağa erişim mümkün — ciddi güvenlik açığı.',
                    recommendation: 'Bu ayar asla true yapılmamalıdır.'
                });
            }
            return this.setAllowUniversalAccessFromFileURLs(flag);
        };
    } catch (e) { /* WebSettings yok */ }

    //  7. WebView.addJavascriptInterface() — JS Bridge 
    try {
        var WebView4 = Java.use('android.webkit.WebView');

        WebView4.addJavascriptInterface.implementation = function (obj, name) {
            send({
                category: 'M7: Client Code Quality',
                severity: 'HIGH',
                title: 'WebView JavaScript Interface Eklendi',
                description: 'addJavascriptInterface() çağrıldı. ' +
                             'JavaScript kodu native Android metodlarına erişebilir. ' +
                             'Interface adı: ' + name,
                recommendation: 'API level 17 altında ciddi RCE riski. @JavascriptInterface annotation\'ı kullanın.'
            });
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) { /* WebView yok */ }

});
