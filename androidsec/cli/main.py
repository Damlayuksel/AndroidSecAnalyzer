"""
Main CLI entry point using Click
Click framework ile komut satırı arayüzü
"""

import click

from androidsec.version import __version__
from androidsec.cli.commands.scan import scan
from androidsec.cli.commands.report import report
from androidsec.cli.commands.active_hack import active_hack


@click.group()
@click.version_option(version=__version__, prog_name="androidsec")
@click.option('-v', '--verbose', count=True, help='Increase verbosity (-v, -vv, -vvv)')
@click.pass_context
def cli(ctx, verbose):
    """
    AndroidSecAnalyzer - Android Security Analysis Tool
    
    Android uygulamalarının güvenlik analizini yapar.
    Statik ve dinamik analiz yöntemlerini kullanarak
    OWASP Mobile Top 10 zafiyetlerini tespit eder.
    
    Örnek kullanım:
    
        \b
        # Tam analiz
        androidsec scan app.apk
        
        \b
        # Sadece statik analiz
        androidsec scan app.apk --static-only
        
        \b
        # HTML rapor oluştur
        androidsec scan app.apk --output html
    """
    # Context object oluştur (alt komutlar için)
    ctx.ensure_object(dict)
    
    # Verbosity seviyesini ayarla
    if verbose == 0:
        ctx.obj['log_level'] = 'INFO'
    elif verbose == 1:
        ctx.obj['log_level'] = 'DEBUG'
    else:
        ctx.obj['log_level'] = 'DEBUG'


# Alt komutları ekle
cli.add_command(scan)
cli.add_command(report)
cli.add_command(active_hack)


if __name__ == '__main__':
    cli()
