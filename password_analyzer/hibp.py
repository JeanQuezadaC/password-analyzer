"""Comprobación de filtraciones con la API Pwned Passwords de Have I Been Pwned.

Usa k-anonimato: solo se envían los 5 primeros caracteres del hash SHA-1.
La contraseña (y su hash completo) nunca salen del equipo.
Documentación: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "password-analyzer-cli"


class HIBPError(Exception):
    """No se pudo consultar la API."""


def sha1_split(password: str) -> tuple[str, str]:
    """Devuelve (prefijo de 5 caracteres, sufijo) del SHA-1 en mayúsculas."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_response(body: str, suffix: str) -> int:
    """Busca nuestro sufijo en la respuesta 'SUFIJO:VECES' de la API."""
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            return int(count.strip())
    return 0


def times_pwned(password: str, timeout: float = 10.0) -> int:
    """Número de veces que la contraseña aparece en filtraciones (0 = ninguna)."""
    prefix, suffix = sha1_split(password)
    request = urllib.request.Request(
        API_URL.format(prefix=prefix),
        # Add-Padding evita que alguien que espíe el tráfico deduzca el resultado
        # por el tamaño de la respuesta.
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise HIBPError(f"No se pudo contactar con la API: {exc}") from exc
    return parse_response(body, suffix)
