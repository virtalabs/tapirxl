"""Top-level CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(
    name="mdt",
    help="Medical Device Traffic — passive device identification",
    no_args_is_help=True,
)

_COMPILED_JSON_DEFAULT = Path("agents/compiled_fusion.json")
_COMPILED_NORMALIZE_DEFAULT = Path("agents/compiled_normalize.json")


@app.command("agent")
def agent(
    pcap: Annotated[
        str | None, typer.Argument(help="Path to PCAP file (omit to read envelopes from stdin)")
    ] = None,
    no_llm: Annotated[bool, typer.Option("--no-llm")] = False,
    compile_: Annotated[bool, typer.Option("--compile")] = False,
    compile_normalize: Annotated[bool, typer.Option("--compile-normalize")] = False,
    rlm: Annotated[bool, typer.Option("--rlm")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
    filter_conf: Annotated[str, typer.Option("--filter")] = "L",
    models_path: Annotated[str | None, typer.Option("--models")] = None,
    compiled_json_path: Annotated[str | None, typer.Option("--compiled-json")] = None,
    compiled_normalize_path: Annotated[
        str | None, typer.Option("--compiled-normalize-json")
    ] = None,
    output: Annotated[str | None, typer.Option("--output")] = None,
) -> None:
    """Full pipeline: (PCAP | stdin envelopes) → triage → (optional LM) → markdown/JSONL."""
    import json

    from tapirxl.agent.cli import run_agent

    compiled_json = Path(compiled_json_path) if compiled_json_path else _COMPILED_JSON_DEFAULT
    compiled_normalize = (
        Path(compiled_normalize_path) if compiled_normalize_path else _COMPILED_NORMALIZE_DEFAULT
    )

    # Redirect stdout for JSONL mode (N6)
    _jsonl_stdout = None
    if json_out:
        _jsonl_stdout = sys.stdout
        sys.stdout = sys.stderr

    needs_lm = not no_llm
    cfg = None
    if needs_lm:
        from tapirxl.agent.config import load_model_config

        cfg = load_model_config(Path(models_path) if models_path else None)

    if compile_normalize:
        import dspy

        from tapirxl.agent.adapters.ollama_lm import build_lm_pair
        from tapirxl.agent.compile.compile_normalize import run_compile_normalize

        _, norm_lm = build_lm_pair(cfg)
        dspy.configure(lm=norm_lm)
        typer.echo("Running BootstrapFewShot compilation (NormalizeSignal)...", err=True)
        run_compile_normalize(compiled_normalize)
        if not compile_:
            return

    if compile_:
        import dspy

        from tapirxl.agent.adapters.ollama_lm import build_lm_pair
        from tapirxl.agent.compile.compile_fusion import run_compile

        fuse_lm, _ = build_lm_pair(cfg)
        dspy.configure(lm=fuse_lm)
        typer.echo("Running BootstrapFewShot compilation (FuseSignals)...", err=True)
        run_compile(compiled_json)
        return

    # Load envelopes: PCAP → parser, or read from stdin
    if pcap is not None:
        from tapirxl.parser.pipeline import run as _parse_run

        typer.echo("Layer 1-2: extracting packets and building envelopes...", err=True)
        register = _parse_run(pcap)
    else:
        register = []
        for line in sys.stdin:
            line = line.strip()
            if line:
                register.append(json.loads(line))

    typer.echo(f"  {len(register)} host envelopes", err=True)

    pcap_stem = Path(pcap).stem if pcap else "stdin"

    run_agent(
        register,
        no_llm=no_llm,
        compiled_json=compiled_json,
        compiled_normalize=compiled_normalize,
        emit_json=json_out,
        rlm=rlm,
        filter_threshold=filter_conf,
        pcap_stem=pcap_stem,
        output=Path(output) if output else None,
        jsonl_stdout=_jsonl_stdout,
        cfg=cfg,
    )


@app.command("parse")
def parse(
    pcap: Annotated[str, typer.Argument(help="Path to input PCAP file")],
) -> None:
    """Parse PCAP → one HostEnvelope JSON per line on stdout."""
    from tapirxl.parser.cli import main as _parse_main

    _parse_main(pcap)


@app.command("fixtures")
def fixtures(
    output: Annotated[str | None, typer.Option("--output", "-o", help="Output PCAP path")] = None,
    seed_time: Annotated[
        str | None, typer.Option("--seed-time", help="ISO8601 UTC timestamp")
    ] = None,
) -> None:
    """Regenerate synthetic PCAP fixture."""
    from tapirxl.fixtures.cli import main as _fixtures_main

    argv: list[str] = []
    if output:
        argv += ["--output", output]
    if seed_time:
        argv += ["--seed-time", seed_time]
    _fixtures_main(argv)
