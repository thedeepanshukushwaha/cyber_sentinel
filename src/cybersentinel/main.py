"""Entry point for CyberSentinel — Automated Penetration Testing Toolkit."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import List, Optional

try:
    from cybersentinel.config import AUTHORIZED_USE_NOTICE, get_anthropic_api_key
    from cybersentinel.core.scheduler import TaskScheduler
    from cybersentinel.reporting.report_gen import generate_report
except ImportError:
    from config import AUTHORIZED_USE_NOTICE, get_anthropic_api_key
    from modules.scheduler import TaskScheduler
    from reports.report_gen import generate_report

DEFAULT_PORTS: List[int] = [80, 443]


def parse_ports(port_string: str) -> List[int]:
    """Parse comma-separated port numbers or hyphen-separated ranges."""
    ports: List[int] = []
    for part in port_string.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text.strip())
            end = int(end_text.strip())
            if start <= end:
                ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the CLI command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="cybersentinel",
        description="CyberSentinel — Automated Penetration Testing & AI Security Analysis Toolkit",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=AUTHORIZED_USE_NOTICE,
    )
    parser.add_argument(
        "--gui",
        help="Launch the graphical user interface instead of the CLI",
        action="store_true",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target hostname or IP address to assess when using CLI mode",
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated ports or ranges to scan, e.g. 22,80,443 or 8000-8010",
        default=None,
    )
    parser.add_argument(
        "--output",
        help="Optional HTML report output path",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--no-ai",
        help="Skip AI analysis and use only local scan results",
        action="store_true",
    )
    parser.add_argument(
        "--ai-model",
        help="Model identifier to use for AI analysis",
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Increase verbosity level (-v for INFO, -vv for DEBUG)",
        action="count",
        default=0,
    )
    return parser


def configure_logging(verbosity: int) -> None:
    """Configure system logging level based on verbosity count."""
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _run_cli_scan(args: argparse.Namespace) -> int:
    if not args.target:
        raise ValueError("A target must be provided when running in CLI mode. Example: cybersentinel 127.0.0.1")

    print("\n" + "=" * 60)
    print("  CyberSentinel — Automated Security Assessment Toolkit")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] Notice: {AUTHORIZED_USE_NOTICE}\n")

    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS

    scheduler = TaskScheduler()
    scheduler.schedule_default_pipeline(args.target, ports=ports)

    ai_api_key = None if args.no_ai else get_anthropic_api_key()
    run_ai = not args.no_ai and bool(ai_api_key)

    if not args.no_ai and not ai_api_key:
        logging.warning("No AI API key found; continuing with local assessment findings.")

    executed_results = scheduler.execute_pipeline(
        run_ai_analysis=run_ai,
        ai_model=args.ai_model,
        ai_api_key=ai_api_key,
    )

    results = scheduler.get_aggregated_results(args.target)
    risk_summary = scheduler.build_overall_risk_summary()
    report_path = generate_report(
        args.target,
        results,
        risk_summary=risk_summary,
        output_path=args.output,
    )

    print(f"[+] Completed scan for target: {args.target}")
    print(f"[+] Generated report: {report_path}")
    print(f"[+] Total tasks executed: {len(executed_results)}")
    print(
        f"[+] Risk summary: Severity={risk_summary.get('severity', 'Unknown')} (Score: {risk_summary.get('highest_score', 0)}/100)\n"
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main execution dispatcher."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    configure_logging(args.verbose)

    if args.gui:
        try:
            try:
                from cybersentinel.gui.main_window import run_gui
            except ImportError:
                from gui.main_window import run_gui
        except ImportError as exc:
            logging.error("Unable to import GUI dependencies (PyQt5 required): %s", exc)
            print("[-] Error: GUI dependencies not installed. Install with: pip install PyQt5")
            return 1
        return run_gui()

    if not args.target:
        parser.print_help()
        return 1

    return _run_cli_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
