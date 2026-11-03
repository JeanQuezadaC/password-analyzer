"""Análisis local de la fortaleza de una contraseña.

Todo lo de este módulo se ejecuta en local: la contraseña nunca sale del equipo.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field

# Contraseñas muy comunes (extracto de listas públicas de filtraciones).
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "password", "qwerty", "123123",
    "111111", "abc123", "1234567", "password1", "12345", "1234567890",
    "000000", "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein",
    "football", "qwerty123", "contraseña", "contrasena", "hola123",
    "barcelona", "realmadrid", "superman", "princesa", "tequiero",
}

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")

# Intentos por segundo de un ataque offline con GPU contra un hash rápido.
GUESSES_PER_SECOND = 1e10

STRENGTH_LABELS = ("Muy débil", "Débil", "Aceptable", "Fuerte", "Muy fuerte")


@dataclass
class AnalysisResult:
    length: int
    charset_size: int
    entropy_bits: float
    crack_time_seconds: float
    score: int  # 0 (muy débil) a 4 (muy fuerte)
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return STRENGTH_LABELS[self.score]


def charset_size(password: str) -> int:
    """Tamaño del alfabeto que usa la contraseña."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        size += 33
    if any(ord(c) > 127 for c in password):  # ñ, tildes, emojis...
        size += 100
    return size


def entropy(password: str) -> float:
    """Entropía teórica en bits: longitud * log2(alfabeto)."""
    size = charset_size(password)
    if not password or size == 0:
        return 0.0
    return len(password) * math.log2(size)


def _has_sequence(password: str, min_len: int = 4) -> bool:
    """Detecta secuencias como 'abcd', '4321' o 'qwer'."""
    lower = password.lower()
    sources = [string.ascii_lowercase, string.digits, *KEYBOARD_ROWS]
    for src in sources:
        for seq in (src, src[::-1]):
            for i in range(len(seq) - min_len + 1):
                if seq[i:i + min_len] in lower:
                    return True
    return False


def find_issues(password: str) -> list[str]:
    """Devuelve una lista de debilidades encontradas."""
    issues = []
    lower = password.lower()

    if lower in COMMON_PASSWORDS:
        issues.append("Es una de las contraseñas más usadas del mundo")
    if len(password) < 8:
        issues.append("Tiene menos de 8 caracteres")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Repite el mismo carácter 3 o más veces seguidas")
    if _has_sequence(password):
        issues.append("Contiene una secuencia predecible (abcd, 1234, qwer...)")
    if re.search(r"(19|20)\d{2}", password):
        issues.append("Contiene lo que parece un año (fácil de adivinar)")
    if password.isdigit():
        issues.append("Solo tiene números")
    elif password.isalpha():
        issues.append("Solo tiene letras")
    return issues


def suggestions_for(password: str) -> list[str]:
    tips = []
    if len(password) < 12:
        tips.append("Usa al menos 12 caracteres; la longitud es lo que más suma")
    if not re.search(r"[A-Z]", password):
        tips.append("Añade mayúsculas")
    if not re.search(r"[a-z]", password):
        tips.append("Añade minúsculas")
    if not re.search(r"\d", password):
        tips.append("Añade números")
    if not re.search(r"[^A-Za-z0-9]", password):
        tips.append("Añade símbolos (!, #, $, ...)")
    tips.append("Considera una frase de contraseña: 4-5 palabras aleatorias")
    tips.append("Usa un gestor de contraseñas (Bitwarden, KeePassXC)")
    return tips


def score(entropy_bits: float, issues: list[str]) -> int:
    """Puntuación de 0 a 4 a partir de la entropía, penalizada por debilidades."""
    if entropy_bits < 28:
        value = 0
    elif entropy_bits < 36:
        value = 1
    elif entropy_bits < 60:
        value = 2
    elif entropy_bits < 80:
        value = 3
    else:
        value = 4

    value -= len(issues)
    if any("más usadas" in i for i in issues):
        value = 0
    return max(0, min(4, value))


def crack_time(entropy_bits: float) -> float:
    """Tiempo medio (segundos) para romperla por fuerza bruta: la mitad del espacio."""
    return (2 ** entropy_bits) / 2 / GUESSES_PER_SECOND


def format_duration(seconds: float) -> str:
    units = [
        ("siglos", 3600 * 24 * 365 * 100),
        ("años", 3600 * 24 * 365),
        ("días", 3600 * 24),
        ("horas", 3600),
        ("minutos", 60),
        ("segundos", 1),
    ]
    if seconds < 1:
        return "instantáneo"
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "siglos" and value > 1e6:
                return "más de un millón de siglos"
            return f"{value:,.0f} {name}".replace(",", ".")
    return "instantáneo"


def analyze(password: str) -> AnalysisResult:
    """Punto de entrada principal: analiza la contraseña en local."""
    bits = entropy(password)
    issues = find_issues(password)
    # Las contraseñas comunes caen en segundos con un ataque de diccionario,
    # da igual lo que diga la entropía teórica.
    is_common = password.lower() in COMMON_PASSWORDS
    return AnalysisResult(
        length=len(password),
        charset_size=charset_size(password),
        entropy_bits=round(bits, 1),
        crack_time_seconds=0.0 if is_common else crack_time(bits),
        score=score(bits, issues),
        issues=issues,
        suggestions=suggestions_for(password),
    )
