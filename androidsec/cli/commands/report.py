"""
Report command - Generate reports from previous analysis
Önceki analizlerden rapor oluşturma
"""

import json
import click
from pathlib import Path


@click.command()
@click.option(
    '--input',
    'input_file',
    type=click.Path(exists=True),
    help='Önceki analiz JSON çıktısı'
)
@click.option(
    '-f', '--format',
    type=click.Choice(['html', 'json'], case_sensitive=False),
    default='html',
    help='Rapor formatı'
)
@click.option(
    '--output',
    type=click.Path(),
    help='Çıktı dosyası yolu'
)
def report(input_file, format, output):
    """
    Önceki analizlerden rapor oluştur
    
    Kaydedilmiş bir analiz sonucundan rapor oluşturur.
    
    Örnek:
    
        \b
        androidsec report --input output/reports/result.json --format html
    """
    if not input_file:
        click.echo("Hata: --input parametresi gerekli!", err=True)
        click.echo("Kullanım: androidsec report --input <analiz_json> --format html", err=True)
        return

    click.echo(f"\nRapor oluşturuluyor...")
    click.echo(f"   Kaynak: {input_file}")
    click.echo(f"   Format: {format}")

    try:
        # JSON dosyasını oku
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        from androidsec.reporting.generator import ReportGenerator
        generator = ReportGenerator()

        report_path = generator.generate(
            data=data,
            format=format,
            output_path=output,
        )

        click.echo(f"\nRapor oluşturuldu: {report_path}")

    except json.JSONDecodeError:
        click.echo(f"\nHata: Geçersiz JSON dosyası: {input_file}", err=True)
    except Exception as e:
        click.echo(f"\nHata: {str(e)}", err=True)
