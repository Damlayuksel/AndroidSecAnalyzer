"""
androidsec/reporting/html_formatter.py
Web arayüzüyle birebir aynı temada HTML raporu üretir.
"""

import logging
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class HTMLFormatter:

    SEVERITY_COLORS = {
        "CRITICAL": "#e63946",
        "HIGH":     "#d29922",
        "MEDIUM":   "#e3b341",
        "LOW":      "#2d9e5f",
        "INFO":     "#4a9eff",
    }

    def format(self, data: Dict[str, Any], output_path: str) -> str:
        logger.info("HTML raporu oluşturuluyor: %s", output_path)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        html = self._build_html(
            apk_info=data.get("apk_info", {}),
            risk=data.get("risk", {}),
            statistics=data.get("statistics", {}),
            findings=data.get("findings", []),
            by_owasp=data.get("by_owasp", {}),
            analysis_time=data.get("analysis_time", 0),
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info("HTML raporu oluşturuldu: %s", path)
        return str(path)

    def _build_html(self, apk_info, risk, statistics, findings, by_owasp, analysis_time) -> str:
        now        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        risk_score = risk.get("score", 0)
        risk_level = (risk.get("level", "NONE")).upper()
        risk_color = self.SEVERITY_COLORS.get(risk_level, "#4a9eff")
        sev_counts = statistics.get("by_severity", {})
        bar_width  = min(risk_score * 10, 100)

        # severity sırasına göre sırala
        order     = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        sorted_f  = sorted(findings, key=lambda f: order.get(f.get("severity","INFO"),5))
        cards_html = self._build_finding_cards(sorted_f)
        owasp_html = self._build_owasp_section(by_owasp)
        info_html  = self._build_info_grid(apk_info, analysis_time)

        # risk banner renkleri (web arayüzüyle aynı)
        risk_banner_cls = {
            "CRITICAL": "risk-critical",
            "HIGH":     "risk-high",
            "MEDIUM":   "risk-medium",
            "LOW":      "risk-low",
        }.get(risk_level, "risk-low")

        return f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>AndroidSecAnalyzer — Rapor</title>
  <style>
    :root{{
      --bg:#000000;--surface:#0a0a0a;--surface2:#111111;
      --border:#1a1a1a;--border2:#2a2a2a;
      --red:#e63946;--red2:#ff6b6b;--red-dim:rgba(230,57,70,.12);
      --white:#f0f0f0;--muted:#666666;
      --orange:#d29922;--yellow:#e3b341;--green:#2d9e5f;--blue:#4a9eff;
    }}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--white);font-family:'Courier New',monospace;min-height:100vh;font-weight:600}}

    /* CANVAS */
    #mc{{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none}}
    nav,.hero,.wrap{{position:relative;z-index:1}}

    /* NAV */
    nav{{display:flex;align-items:center;gap:16px;padding:16px 40px;border-bottom:1px solid var(--border2);background:rgba(10,10,10,.97);backdrop-filter:blur(4px);position:sticky;top:0;z-index:100}}
    .nav-dot{{width:9px;height:9px;border-radius:50%;background:var(--red);box-shadow:0 0 8px var(--red);animation:blink 2s infinite;flex-shrink:0}}
    @keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:.2}}}}
    .nav-brand{{font-size:17px;font-weight:900;color:var(--red);letter-spacing:2px;text-transform:uppercase}}
    .nav-sub{{font-size:12px;color:var(--white);letter-spacing:1px;font-weight:700}}
    .nav-meta{{margin-left:auto;font-size:11px;color:var(--muted);letter-spacing:.5px}}

    /* HERO */
    .hero{{text-align:center;padding:52px 20px 40px;border-bottom:1px solid var(--border);background:rgba(0,0,0,.85);backdrop-filter:blur(6px)}}
    .hero-tag{{font-size:11px;color:var(--red);letter-spacing:3px;text-transform:uppercase;margin-bottom:14px;font-weight:900}}
    .hero h1{{font-size:32px;font-weight:900;letter-spacing:2px;margin-bottom:8px;text-shadow:0 0 30px rgba(230,57,70,.3)}}
    .hero h1 span{{color:var(--red)}}
    .hero p{{color:#aaaaaa;font-size:13px;letter-spacing:.5px;font-weight:700}}

    /* WRAP */
    .wrap{{max-width:1000px;margin:0 auto;padding:36px 24px;background:rgba(0,0,0,.82);backdrop-filter:blur(6px)}}

    /* SECTION TITLE */
    .sec-title{{font-size:10px;font-weight:900;color:var(--muted);text-transform:uppercase;letter-spacing:2px;margin:32px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--border2)}}

    /* INFO GRID */
    .info-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:4px}}
    .info-card{{background:var(--surface);border:1px solid var(--border2);border-radius:4px;padding:14px 16px}}
    .info-key{{font-size:10px;color:var(--muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}}
    .info-val{{font-size:13px;font-weight:900;color:var(--white);word-break:break-all}}

    /* RISK BANNER */
    .risk-banner{{border-radius:4px;padding:24px 28px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px;border:1px solid}}
    .risk-critical{{background:rgba(230,57,70,.1);border-color:rgba(230,57,70,.4)}}
    .risk-high    {{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3)}}
    .risk-medium  {{background:rgba(227,179,65,.08);border-color:rgba(227,179,65,.3)}}
    .risk-low     {{background:rgba(45,158,95,.08);border-color:rgba(45,158,95,.3)}}
    .risk-left h2{{font-size:22px;font-weight:900;margin-bottom:4px;letter-spacing:2px;color:{risk_color}}}
    .risk-left p{{color:var(--muted);font-size:12px;letter-spacing:.5px}}
    .risk-circle{{width:80px;height:80px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;font-weight:900;border:2px solid {risk_color};color:{risk_color};flex-shrink:0}}
    .score-num{{font-size:20px;line-height:1}}
    .score-den{{font-size:10px;opacity:.6}}
    .risk-bar-bg{{width:100%;height:3px;background:var(--border2);border-radius:2px;margin-top:12px;overflow:hidden}}
    .risk-bar-fill{{height:100%;width:{bar_width}%;background:{risk_color};border-radius:2px}}

    /* STATS */
    .stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-bottom:4px}}
    .stat-card{{background:var(--surface);border:1px solid var(--border2);border-radius:4px;padding:16px;text-align:center}}
    .stat-num{{font-size:26px;font-weight:900;margin-bottom:3px}}
    .stat-label{{font-size:10px;color:var(--muted);letter-spacing:1px;text-transform:uppercase}}

    /* FILTER */
    .filter-row{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}}
    .filter-btn{{padding:4px 12px;border-radius:3px;font-size:10px;font-weight:700;cursor:pointer;border:1px solid var(--border2);background:transparent;color:var(--muted);transition:all .2s;font-family:'Courier New',monospace;letter-spacing:1px;text-transform:uppercase}}
    .filter-btn.active{{border-color:var(--red);color:var(--red);background:var(--red-dim)}}

    /* FINDING CARDS */
    .findings-list{{display:flex;flex-direction:column;gap:6px;margin-bottom:4px}}
    .finding-card{{background:var(--surface);border:1px solid var(--border2);border-radius:4px;padding:12px 14px;display:flex;align-items:flex-start;gap:10px;cursor:pointer;transition:border-color .2s}}
    .finding-card:hover{{border-color:var(--red2)}}
    .finding-card.open{{border-color:var(--red)}}
    .sev-badge{{padding:2px 7px;border-radius:2px;font-size:9px;font-weight:900;flex-shrink:0;margin-top:2px;letter-spacing:1px}}
    .sev-CRITICAL{{background:rgba(230,57,70,.2);color:#e63946}}
    .sev-HIGH    {{background:rgba(210,153,34,.2);color:#d29922}}
    .sev-MEDIUM  {{background:rgba(227,179,65,.15);color:#e3b341}}
    .sev-LOW     {{background:rgba(45,158,95,.15);color:#2d9e5f}}
    .sev-INFO    {{background:rgba(74,158,255,.15);color:#4a9eff}}
    .finding-content h4{{font-size:13px;margin-bottom:3px;color:var(--white);font-weight:900;letter-spacing:.5px}}
    .finding-content p{{font-size:11px;color:var(--muted);letter-spacing:.3px}}
    .finding-detail{{display:none;margin-top:10px;padding-top:10px;border-top:1px solid var(--border);font-size:12px;color:#aaaaaa;line-height:1.7}}
    .finding-card.open .finding-detail{{display:block}}

    /* OWASP */
    .owasp-item{{background:var(--surface);border:1px solid var(--border2);border-radius:4px;margin-bottom:6px;overflow:hidden}}
    .owasp-hdr{{padding:12px 16px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:background .2s}}
    .owasp-hdr:hover{{background:var(--red-dim)}}
    .owasp-cat{{font-size:12px;font-weight:900;letter-spacing:.5px}}
    .owasp-count{{padding:2px 8px;border-radius:2px;font-size:10px;font-weight:900;letter-spacing:1px;background:var(--red);color:#000}}
    .owasp-count.zero{{background:var(--border2);color:var(--muted)}}
    .owasp-body{{display:none;padding:12px 16px;border-top:1px solid var(--border)}}
    .owasp-item.open .owasp-body{{display:block}}
    .owasp-finding{{padding:6px 0;border-bottom:1px solid var(--border);font-size:12px}}
    .owasp-finding:last-child{{border:none}}

    /* FOOTER */
    footer{{text-align:center;padding:24px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);margin-top:40px;letter-spacing:1px}}
    footer span{{color:var(--red)}}
  </style>
</head>
<body>

<canvas id="mc"></canvas>

<nav>
  <div class="nav-dot"></div>
  <div class="nav-brand">AndroidSecAnalyzer</div>
  <div class="nav-sub"> Guvenlik Raporu</div>
  <div class="nav-meta">{now} &nbsp;|&nbsp; {analysis_time:.2f}s</div>
</nav>

<div class="hero">
  <div class="hero-tag"> Android Uygulama Guvenlik Analizi</div>
  <h1>Guvenlik <span>Raporu</span></h1>
  <p>OWASP Mobile Top 10 standartlarina gore otomatik analiz</p>
</div>

<div class="wrap">

  <div class="sec-title"> APK Bilgileri</div>
  {info_html}

  <div class="sec-title"> Risk Skoru</div>
  <div class="risk-banner {risk_banner_cls}">
    <div class="risk-left">
      <h2>{risk_level}</h2>
      <p>{len(findings)} bulgu &nbsp;//&nbsp; {analysis_time:.1f}s</p>
      <div class="risk-bar-bg"><div class="risk-bar-fill"></div></div>
    </div>
    <div class="risk-circle">
      <span class="score-num">{risk_score:.1f}</span>
      <span class="score-den">/10</span>
    </div>
  </div>

  <div class="sec-title"> Ozet</div>
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-num" style="color:#e63946">{sev_counts.get('CRITICAL',0)}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#d29922">{sev_counts.get('HIGH',0)}</div><div class="stat-label">High</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#e3b341">{sev_counts.get('MEDIUM',0)}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#2d9e5f">{sev_counts.get('LOW',0)}</div><div class="stat-label">Low</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#4a9eff">{sev_counts.get('INFO',0)}</div><div class="stat-label">Info</div></div>
    <div class="stat-card"><div class="stat-num" style="color:var(--red)">{len(findings)}</div><div class="stat-label">Toplam</div></div>
  </div>

  <div class="sec-title">// Tum Bulgular</div>
  <div class="filter-row" id="filters"></div>
  <div class="findings-list" id="list">{cards_html}</div>

  <div class="sec-title"> OWASP Mobile Top 10</div>
  {owasp_html}

</div>

<footer><span>AndroidSecAnalyzer</span> &nbsp;//&nbsp; OWASP Mobile Top 10 &nbsp;//&nbsp; {now}</footer>

<script>
  // Matrix yağmuru
  (function(){{
    const canvas=document.getElementById('mc'),ctx=canvas.getContext('2d');
    const chars='01アイウエオABCDEF0123456789#$%@!';
    const fs=14;let cols,drops;
    function resize(){{canvas.width=window.innerWidth;canvas.height=window.innerHeight;cols=Math.floor(canvas.width/fs);drops=Array.from({{length:cols}},()=>Math.random()*-(canvas.height/fs));}}
    function draw(){{
      ctx.fillStyle='rgba(0,0,0,0.08)';ctx.fillRect(0,0,canvas.width,canvas.height);
      for(let i=0;i<drops.length;i++){{
        const x=i*fs,y=drops[i]*fs;if(y<0){{drops[i]++;continue;}}
        ctx.font=`bold ${{fs}}px 'Courier New'`;ctx.fillStyle='#ffffff';ctx.fillText(chars[Math.floor(Math.random()*chars.length)],x,y);
        ctx.fillStyle='#ff1a1a';ctx.fillText(chars[Math.floor(Math.random()*chars.length)],x,y-fs);
        ctx.fillStyle='#8b0000';ctx.font=`${{fs}}px 'Courier New'`;ctx.fillText(chars[Math.floor(Math.random()*chars.length)],x,y-fs*2);
        drops[i]++;if(y>canvas.height&&Math.random()>.97)drops[i]=Math.random()*-30;
      }}
    }}
    resize();window.addEventListener('resize',resize);setInterval(draw,40);
  }})();

  // Finding card toggle
  document.querySelectorAll('.finding-card').forEach(c=>{{
    c.addEventListener('click',()=>c.classList.toggle('open'));
  }});

  // OWASP toggle
  document.querySelectorAll('.owasp-hdr').forEach(h=>{{
    h.addEventListener('click',()=>h.closest('.owasp-item').classList.toggle('open'));
  }});

  // Severity filter
  const allCards=[...document.querySelectorAll('.finding-card')];
  const fr=document.getElementById('filters');
  ['ALL','CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(f=>{{
    const btn=document.createElement('button');
    btn.className='filter-btn'+(f==='ALL'?' active':'');
    btn.textContent=f==='ALL'?'TUMU':f;
    btn.onclick=()=>{{
      fr.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      allCards.forEach(c=>{{
        c.style.display=(f==='ALL'||c.dataset.sev===f)?'flex':'none';
      }});
    }};
    fr.appendChild(btn);
  }});
</script>
</body>
</html>"""

    def _build_info_grid(self, apk_info, analysis_time) -> str:
        items = [
            ("Dosya Adi",   apk_info.get("file_name", "N/A")),
            ("Paket Adi",   apk_info.get("package_name", "N/A")),
            ("Versiyon",    f"{apk_info.get('version_name','N/A')} (code: {apk_info.get('version_code','N/A')})"),
            ("Boyut",       self._format_size(apk_info.get("file_size", 0))),
        ]
        html = '<div class="info-grid">'
        for k, v in items:
            html += f'<div class="info-card"><div class="info-key">{k}</div><div class="info-val">{v}</div></div>'
        html += '</div>'
        return html

    def _build_finding_cards(self, findings: List[Dict]) -> str:
        if not findings:
            return '<div style="color:var(--muted);text-align:center;padding:24px;font-size:12px">// Bulgu bulunamadi.</div>'
        html = ""
        for f in findings:
            sev  = f.get("severity", "INFO")
            desc = (f.get("description") or "").replace("\n", "<br>")
            rec  = f.get("recommendation", "")
            rec_html = f"<br><br><strong>Oneri:</strong><br>{rec}" if rec else ""
            file_str = f" // {f.get('file','')}" if f.get("file") else ""
            html += f"""<div class="finding-card" data-sev="{sev}">
  <span class="sev-badge sev-{sev}">{sev}</span>
  <div class="finding-content">
    <h4>{f.get('title','Bulgu')}</h4>
    <p>{f.get('category','')}{file_str}</p>
    <div class="finding-detail"><strong>Aciklama:</strong><br>{desc}{rec_html}</div>
  </div>
</div>"""
        return html

    def _build_owasp_section(self, by_owasp: Dict[str, List]) -> str:
        if not by_owasp:
            return '<div style="color:var(--muted);font-size:12px">// OWASP siniflandirmasi bulunamadi.</div>'
        html = ""
        for category, cat_findings in by_owasp.items():
            count     = len(cat_findings)
            cnt_cls   = "owasp-count" if count else "owasp-count zero"
            items_html = ""
            for f in cat_findings[:10]:
                sev = f.get("severity","INFO")
                col = self.SEVERITY_COLORS.get(sev,"#888")
                desc = (f.get("description") or "")[:100]
                items_html += f'<div class="owasp-finding"><span style="color:{col};font-weight:900">[{sev}]</span> {f.get("title","N/A")} — <span style="color:var(--muted)">{desc}</span></div>'
            if count > 10:
                items_html += f'<div class="owasp-finding" style="color:var(--muted)">... ve {count-10} daha fazla bulgu</div>'
            if not items_html:
                items_html = '<div style="color:var(--muted);font-size:12px;padding:4px 0">// Bu kategoride bulgu bulunamadi.</div>'
            html += f"""<div class="owasp-item">
  <div class="owasp-hdr"><span class="owasp-cat">{category}</span><span class="{cnt_cls}">{count}</span></div>
  <div class="owasp-body">{items_html}</div>
</div>"""
        return html

    def _format_size(self, size_bytes: int) -> str:
        if not size_bytes:
            return "N/A"
        for unit in ["B","KB","MB","GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
