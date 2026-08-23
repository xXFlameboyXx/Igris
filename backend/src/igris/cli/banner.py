"""CLI Banner rendering module for Igris using Rich."""

from __future__ import annotations

import sys
from typing import Any

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (OSError, ValueError):
        pass

from rich.align import Align
from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

# Default ASCII Art for IGRIS
DEFAULT_ASCII_ART = r"""
██╗   ██████╗   ██████╗   ██╗  ███████╗
██║  ██╔════╝   ██╔══██╗  ██║  ██╔════╝
██║  ██║  ███╗  ██████╔╝  ██║  ███████╗
██║  ██║   ██║  ██╔══██╗  ██║  ╚════██║
██║  ╚██████╔╝  ██║  ██║  ██║  ███████║
╚═╝   ╚═════╝   ╚═╝  ╚═╝  ╚═╝  ╚══════╝
""".strip("\n")


def build_igris_banner(
    *,
    ascii_art: str | None = None,
    github_url: str = "https://github.com/xXFlameboyXx/Igris",
    discord_url: str = "https://discord.gg/Gg2rjRx8yF",
    target_url: str = "http://127.0.0.1:8000",
    version: str = "v0.1.0",
) -> Panel:
    """Build a styled Rich Panel matching the cyber-forensics red theme with middle symmetry."""
    art = ascii_art if ascii_art else DEFAULT_ASCII_ART

    # ASCII header lines (centered per line for perfect symmetry)
    art_clean = "\n".join(line.strip() for line in art.strip("\n").splitlines())
    header_lines = [Align.center(Text(line, style="bold red")) for line in art_clean.splitlines()]

    # Full form & description
    desc_text = Text(
        "Intelligent Graph-based Reverse-engineering & Inspection System",
        style="bold white",
        justify="center",
    )

    # Links & metadata line (clickable hyperlinks across Windows and Linux)
    links_text = Text(justify="center")
    links_text.append(
        github_url,
        style=Style(color="bright_red", underline=True, link=github_url),
    )
    links_text.append("  •  ", style="dim red")
    links_text.append(
        discord_url,
        style=Style(color="bright_red", underline=True, link=discord_url),
    )
    links_text.append(f"\n{version}", style="dim white")

    # Target indicator (clickable hyperlink)
    target_text = Text(justify="center")
    target_text.append("► Web GUI: ", style="bold red")
    target_text.append(
        target_url,
        style=Style(color="bright_white", bold=True, underline=True, link=target_url),
    )

    # Workflow subtitle
    workflow_title = Text("── Analysis Workflow ──", style="bold dark_red", justify="center")

    # Workflow list (symmetrically centered grid)
    steps_table = Table.grid(padding=(0, 2), expand=False)
    steps_table.add_column(style="bold red", justify="right")
    steps_table.add_column(style="bold bright_white", justify="left")
    steps_table.add_column(style="dim white", justify="left")

    steps_table.add_row(
        "1.", "File Intel", "PE/ELF headers, section entropy, string taxonomy, overlay"
    )
    steps_table.add_row(
        "2.", "Disassembly", "Linear sweep, Capstone x86/x64, basic block recovery & CFG"
    )
    steps_table.add_row(
        "3.", "Sandbox", "Synthetic behavior simulation, process tree, registry IOCs"
    )
    steps_table.add_row(
        "4.", "ATT&CK Matrix", "MITRE technique mapping, epistemological risk scoring"
    )

    # Assemble all elements in a centered grid stack
    content = Table.grid(padding=(0, 0), expand=False)
    content.add_column(justify="center")
    for h in header_lines:
        content.add_row(h)
    content.add_row("")
    content.add_row(Align.center(desc_text))
    content.add_row("")
    content.add_row(Align.center(links_text))
    content.add_row("")
    content.add_row(Align.center(target_text))
    content.add_row("")
    content.add_row(Align.center(workflow_title))
    content.add_row("")
    content.add_row(Align.center(steps_table))

    return Panel(
        Align.center(content),
        border_style="red",
        box=ROUNDED,
        padding=(1, 3),
        title="[bold red] IGRIS CYBER FORENSICS [/bold red]",
        title_align="center",
        expand=False,
    )


def print_banner(
    console: Console | None = None,
    **kwargs: Any,
) -> None:
    """Print the formatted banner to the provided or default console."""
    c = console or Console()
    panel = build_igris_banner(**kwargs)
    c.print(Align.center(panel))


if __name__ == "__main__":
    print_banner()
