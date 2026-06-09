"""
Progress bar and UI utilities for CLI
CLI için progress bar ve UI yardımcıları
"""

import click
from typing import Iterator


def show_progress(iterable: Iterator, label: str = "Processing", length: int = None):
    """
    Show a progress bar for an iterable
    
    Args:
        iterable: İşlenecek iterator
        label: Progress bar etiketi
        length: Toplam eleman sayısı (biliniyorsa)
    
    Örnek:
        for item in show_progress(items, "Analyzing files"):
            process(item)
    """
    with click.progressbar(
        iterable,
        label=label,
        length=length,
        show_eta=True,
        show_percent=True
    ) as bar:
        for item in bar:
            yield item


def print_header(text: str, char: str = "="):
    """
    Print a formatted header
    Başlık yazdır
    
    Args:
        text: Başlık metni
        char: Çizgi karakteri
    """
    width = 60
    click.echo("\n" + char * width)
    click.echo(text.center(width))
    click.echo(char * width + "\n")


def print_section(title: str):
    """
    Print a section title
    Bölüm başlığı yazdır
    """
    click.echo(f"\n{title}")
    click.echo("-" * len(title))


def print_success(message: str):
    """Print success message in green"""
    click.echo(click.style(f"{message}", fg='green'))


def print_error(message: str):
    """Print error message in red"""
    click.echo(click.style(f"{message}", fg='red'), err=True)


def print_warning(message: str):
    """Print warning message in yellow"""
    click.echo(click.style(f"{message}", fg='yellow'))


def print_info(message: str):
    """Print info message in blue"""
    click.echo(click.style(f"ℹ {message}", fg='blue'))
