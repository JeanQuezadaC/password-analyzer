"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import __version__
from .analyzer import analyze, format_duration
from .hibp import HIBPError, times_pwned

COLORS = ["\033[91m", "\033[91m", "\033[93m", "\033[92m", "\033[92m"]
RESET = "\033[0m"
BOLD = "\033[1m"


def strength_bar(score: int, use_color: bool) -> str:
    filled = "█" * (score + 1) * 4
    empty = "░" * (20 - len(filled))
    bar = filled + empty
    return f"{COLORS[score]}{bar}{RESET}" if use_color else bar


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-analyzer",
        description="Analiza la fortaleza de una contraseña y comprueba si ha sido filtrada.",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="no consultar Have I Been Pwned (solo análisis local)",
    )
    parser.add_argument("--json", action="store_true", help="salida en formato JSON")
    parser.add_argument("--no-color", action="store_true", help="desactivar colores")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # getpass oculta lo que se escribe: la contraseña no queda en pantalla
    # ni en el historial de la terminal (a diferencia de pasarla como argumento).
    password = getpass.getpass("Introduce la contraseña a analizar: ")
    if not password:
        print("No se ha introducido ninguna contraseña.", file=sys.stderr)
        return 1

    result = analyze(password)

    pwned: int | None = None
    pwned_error: str | None = None
    if not args.offline:
        try:
            pwned = times_pwned(password)
        except HIBPError as exc:
            pwned_error = str(exc)

    if pwned:
        result.score = 0  # una contraseña filtrada nunca es segura

    if args.json:
        print(json.dumps({
            "length": result.length,
            "entropy_bits": result.entropy_bits,
            "crack_time": format_duration(result.crack_time_seconds),
            "score": result.score,
            "label": result.label,
            "issues": result.issues,
            "times_pwned": pwned,
            "suggestions": result.suggestions,
        }, ensure_ascii=False, indent=2))
        return 0

    color = not args.no_color and sys.stdout.isatty()
    b, r = (BOLD, RESET) if color else ("", "")

    print()
    print(f"{b}Fortaleza:{r} {strength_bar(result.score, color)} {result.label} ({result.score}/4)")
    print(f"{b}Longitud:{r} {result.length} caracteres")
    print(f"{b}Entropía:{r} {result.entropy_bits} bits")
    print(f"{b}Tiempo estimado para romperla:{r} {format_duration(result.crack_time_seconds)}")
    print("  (fuerza bruta offline a 10.000 millones de intentos/segundo)")

    print()
    if args.offline:
        print("Filtraciones: no comprobado (--offline)")
    elif pwned_error:
        print(f"Filtraciones: no comprobado ({pwned_error})")
    elif pwned:
        print(f"{b}⚠ Filtraciones:{r} aparece {pwned:,} veces en filtraciones conocidas. "
              "¡No la uses!".replace(",", "."))
    else:
        print("✔ Filtraciones: no aparece en ninguna filtración conocida")

    if result.issues:
        print(f"\n{b}Problemas detectados:{r}")
        for issue in result.issues:
            print(f"  - {issue}")

    if result.score < 4:
        print(f"\n{b}Recomendaciones:{r}")
        for tip in result.suggestions:
            print(f"  - {tip}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
