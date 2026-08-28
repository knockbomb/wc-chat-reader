"""Typer app entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from wc_chat_reader.core.config import get_settings
from wc_chat_reader.core.constants import VERSION, WeChatVersion
from wc_chat_reader.core.logger import configure_logging

app = typer.Typer(
    name="wcreader",
    help="WeChat local chat history reader.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.callback()
def _root(
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Enable DEBUG logging.")
    ] = False,
) -> None:
    """Global options."""
    configure_logging(level="DEBUG" if verbose else "INFO")


@app.command()
def version() -> None:
    """Print the package version and exit."""
    console.print(f"wc-chat-reader {VERSION}")


@app.command()
def info() -> None:
    """Detect running WeChat processes and print a summary."""
    from wc_chat_reader.wechat import find_wechat_processes

    procs = find_wechat_processes()
    if not procs:
        console.print("[yellow]No WeChat process found.[/yellow]")
        raise typer.Exit(code=1)

    table = Table(title="Detected WeChat Processes")
    table.add_column("PID", justify="right")
    table.add_column("Version")
    table.add_column("File Version")
    table.add_column("Data Dir")
    table.add_column("Executable")

    for p in procs:
        table.add_row(
            str(p.pid),
            p.version.name,
            p.version_str or "-",
            str(p.data_dir) if p.data_dir else "-",
            str(p.exe_path),
        )
    console.print(table)


@app.command()
def key(
    pid: Annotated[
        Optional[int],
        typer.Option(help="PID of the WeChat process. Autodetected if omitted."),
    ] = None,
    sample_db: Annotated[
        Optional[Path],
        typer.Option(help="Path to a WeChat DB used to validate candidate keys."),
    ] = None,
) -> None:
    """Extract the WeChat database key from the running process."""
    from wc_chat_reader.key import extract_key
    from wc_chat_reader.wechat import find_wechat_processes, select_primary_process

    procs = find_wechat_processes()
    if not procs:
        console.print("[red]No WeChat process found.[/red]")
        raise typer.Exit(code=1)
    primary = select_primary_process(procs)
    proc = next((p for p in procs if p.pid == pid), primary) if pid else primary

    console.print(f"Using PID {proc.pid} ({proc.version.name})")
    result = extract_key(proc, sample_db)
    console.print(f"[green]{result.strategy}[/green]: {result.key.hex()}")


@app.command()
def decrypt(
    key_hex: Annotated[
        Optional[str],
        typer.Option("--key", help="32-byte AES key in hex. Autodetected if omitted."),
    ] = None,
    pid: Annotated[
        Optional[int], typer.Option(help="WeChat PID. Autodetected if omitted.")
    ] = None,
    data_dir: Annotated[
        Optional[Path],
        typer.Option(help="WeChat data directory. Autodetected if omitted."),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(help="Output directory. Defaults to <work_dir>/decrypted."),
    ] = None,
) -> None:
    """Decrypt WeChat database files into an output directory."""
    from wc_chat_reader.decrypt import create_decryptor
    from wc_chat_reader.key import extract_key
    from wc_chat_reader.wechat import find_wechat_processes, select_primary_process

    settings = get_settings()
    procs = find_wechat_processes()
    if not procs:
        console.print("[red]No WeChat process found.[/red]")
        raise typer.Exit(code=1)
    primary = select_primary_process(procs)
    proc = next((p for p in procs if p.pid == pid), primary) if pid else primary
    data = data_dir or proc.data_dir
    if data is None:
        console.print("[red]Could not resolve data directory[/red]")
        raise typer.Exit(code=2)
    if not data.exists():
        console.print(f"[red]Data directory does not exist: {data}[/red]")
        raise typer.Exit(code=2)

    if key_hex:
        key_bytes = bytes.fromhex(key_hex)
    else:
        key_bytes = extract_key(proc).key

    out_root = output or settings.work_dir / "decrypted"
    out_root.mkdir(parents=True, exist_ok=True)

    decryptor = create_decryptor(proc.version)
    ok = 0
    skipped = 0
    failed = 0
    for db_path in sorted(data.rglob("*.db")):
        # WAL / shm files must not be decrypted independently.
        name = db_path.name.lower()
        if name.endswith("-wal") or name.endswith("-shm") or name.endswith(".db-journal"):
            skipped += 1
            continue
        try:
            rel = db_path.relative_to(data)
        except ValueError:
            rel = Path(db_path.name)
        target = out_root / rel
        try:
            decryptor.decrypt_file(key_bytes, db_path, target)
            ok += 1
            console.print(f"[green]✓[/green] {rel}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            console.print(f"[yellow]✗ {rel}: {exc}[/yellow]")
    console.print(
        f"[bold green]Done.[/bold green] Decrypted [green]{ok}[/green] file(s), "
        f"skipped [dim]{skipped}[/dim], failed [red]{failed}[/red]. "
        f"Output: {out_root}"
    )


def _detect_data_dir_version(data_dir: Path) -> WeChatVersion:
    """Best-effort version inference from a decrypted data directory."""
    if any(data_dir.rglob("MicroMsg.db")) or any(data_dir.rglob("MSG0.db")):
        return WeChatVersion.V3
    if any(data_dir.rglob("message*.db")) or any(data_dir.rglob("contact.db")):
        return WeChatVersion.V4
    return WeChatVersion.V4  # Reasonable default for modern installs.


@app.command()
def serve(
    host: Annotated[Optional[str], typer.Option()] = None,
    port: Annotated[Optional[int], typer.Option()] = None,
    data_dir: Annotated[
        Optional[Path],
        typer.Option(help="Decrypted DB directory to serve."),
    ] = None,
    version_flag: Annotated[
        Optional[int],
        typer.Option("--wechat-version", help="3 or 4 (auto if omitted)."),
    ] = None,
) -> None:
    """Run the HTTP + MCP server."""
    import uvicorn

    from wc_chat_reader.api.main import create_app
    from wc_chat_reader.db.repository import Repository
    from wc_chat_reader.wechat import find_wechat_processes, select_primary_process

    settings = get_settings()
    host = host or settings.http_host
    port = port or settings.http_port

    repository: Repository | None = None
    ver_str: str | None = None
    dd_str: str | None = None
    if data_dir is not None:
        wv = (
            WeChatVersion(version_flag)
            if version_flag
            else _detect_data_dir_version(data_dir)
        )
        repository = Repository(data_dir=data_dir, version=wv)
        ver_str = wv.name
        dd_str = str(data_dir)
    else:
        # Prefer the decrypted output produced by `wcreader decrypt`, which
        # is what the README workflow actually serves. Fall back to the raw
        # (still encrypted) WeChat data dir only as a last resort.
        decrypted = settings.work_dir / "decrypted"
        if decrypted.exists() and any(decrypted.rglob("*.db")):
            wv = _detect_data_dir_version(decrypted)
            repository = Repository(data_dir=decrypted, version=wv)
            ver_str = wv.name
            dd_str = str(decrypted)
            console.print(f"[green]Serving decrypted data:[/green] {decrypted}")
        else:
            procs = find_wechat_processes()
            if procs:
                p = select_primary_process(procs)
                console.print(
                    "[yellow]Warning: no decrypted data found "
                    f"({decrypted}).[/yellow]\n"
                    "[yellow]Serving the RAW (still encrypted) WeChat data dir "
                    "will return no usable data. Run `wcreader decrypt` first.[/yellow]"
                )
                repository = Repository(data_dir=p.data_dir, version=p.version)
                ver_str = p.version.name
                dd_str = str(p.data_dir)

    app_obj = create_app(
        settings=settings,
        repository=repository,
        wechat_version_str=ver_str,
        data_dir=dd_str,
    )
    console.print(f"[bold]HTTP + MCP server:[/bold] http://{host}:{port}")
    uvicorn.run(app_obj, host=host, port=port, log_level=settings.log_level.lower())
