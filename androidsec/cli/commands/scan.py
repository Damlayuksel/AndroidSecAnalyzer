"""
Scan command - APK analysis
APK tarama komutu
"""

import click
from pathlib import Path

from androidsec.core.analyzer import AndroidSecAnalyzer
from androidsec.core.config_manager import ConfigManager
from androidsec.core.constants import ANALYSIS_STATIC, ANALYSIS_DYNAMIC, ANALYSIS_FULL
from androidsec.utils.logger import setup_logger


@click.command()
@click.argument('apk_path', type=click.Path(exists=True))
@click.option(
    '--static-only',
    is_flag=True,
    help='Sadece statik analiz yap'
)
@click.option(
    '--dynamic-only',
    is_flag=True,
    help='Sadece dinamik analiz yap'
)
@click.option(
    '-o', '--output',
    multiple=True,
    type=click.Choice(['html', 'json'], case_sensitive=False),
    default=['html'],
    help='Rapor formatı (birden fazla seçilebilir)'
)
@click.option(
    '--output-dir',
    type=click.Path(),
    help='Çıktı klasörü'
)
@click.pass_context
def scan(ctx, apk_path, static_only, dynamic_only, output, output_dir):
    """
    APK dosyasını analiz et
    
    APK_PATH: Analiz edilecek APK dosyasının yolu
    
    Örnekler:
    
        \b
        # Tam analiz (statik + dinamik)
        androidsec scan app.apk
        
        \b
        # Sadece statik analiz
        androidsec scan app.apk --static-only
        
        \b
        # HTML ve JSON rapor oluştur
        androidsec scan app.apk -o html -o json
    """
    # Logger'ı ayarla
    log_level = ctx.obj.get('log_level', 'INFO')
    logger = setup_logger('androidsec', level=log_level)
    
    # Analiz tipini belirle
    if static_only and dynamic_only:
        click.echo("Hata: --static-only ve --dynamic-only birlikte kullanılamaz!", err=True)
        ctx.exit(1)
    
    if static_only:
        analysis_type = ANALYSIS_STATIC
    elif dynamic_only:
        analysis_type = ANALYSIS_DYNAMIC
    else:
        analysis_type = ANALYSIS_FULL
    
    # APK dosya adını al
    apk_name = Path(apk_path).name
    
    # Başlık
    click.echo("\n" + "="*60)
    click.echo("AndroidSecAnalyzer - Android Security Analysis Tool")
    click.echo("="*60 + "\n")
    
    click.echo(f"APK: {apk_name}")
    click.echo(f"Analiz Tipi: {analysis_type}")
    click.echo(f"Rapor Formatı: {', '.join(output)}\n")
    
    try:
        # Analyzer oluştur
        config = ConfigManager()
        analyzer = AndroidSecAnalyzer(config)
        
        # Progress göster
        with click.progressbar(
            length=100,
            label='Analiz yapılıyor',
            show_eta=True
        ) as bar:
            # Analizi başlat
            result = analyzer.analyze(
                apk_path=apk_path,
                analysis_type=analysis_type,
                output_dir=output_dir
            )
            bar.update(100)
        
        # Sonuçları göster
        click.echo("\n" + "="*60)
        click.echo("Analiz Sonuçları")
        click.echo("="*60 + "\n")
        
        click.echo(f"Analiz tamamlandı!")
        click.echo(f"Süre: {result.analysis_time:.2f} saniye")
        click.echo(f"Statik bulgular: {len(result.static_findings)}")
        click.echo(f"Dinamik bulgular: {len(result.dynamic_findings)}")
        click.echo(f"Risk Skoru: {result.risk_score:.2f}/10.0")
        
        # Risk seviyesini belirle
        if result.risk_score >= 7.0:
            risk_level = click.style("YÜKSEK", fg='red', bold=True)
        elif result.risk_score >= 5.0:
            risk_level = click.style("ORTA", fg='yellow', bold=True)
        else:
            risk_level = click.style("DÜŞÜK", fg='green', bold=True)
        
        click.echo(f"Risk Seviyesi: {risk_level}\n")
        
        # Rapor oluştur
        if output:
            click.echo("Raporlar oluşturuluyor...")
            for fmt in output:
                report_path = analyzer.generate_report(result, format=fmt)
                click.echo(f"  {fmt.upper()}: {report_path}")
        
        click.echo("\n" + "="*60 + "\n")
        
    except Exception as e:
        click.echo(f"\nHata: {str(e)}", err=True)
        logger.error(f"Scan failed: {e}", exc_info=True)
        ctx.exit(1)
