#!/usr/bin/env python3
"""Build a tracked-file license inventory from a ScanCode JSON result.

This script is intentionally conservative: a package-level license is inherited
only where the repository contains an applicable license or a clear declaration.
Unlicensed third-party subtrees are marked for manual review.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path


ROOT_EFFECTIVE = "Apache-2.0 (effective 2026-01-01; formerly BUSL-1.1)"

EXT_SCOPES = {
    "arm32-neon-salsa2012-asm": ("LicenseRef-Public-Domain", "ext/arm32-neon-salsa2012-asm/README.md"),
    "cpp-httplib": ("MIT", "per-file header in ext/cpp-httplib/httplib.h"),
    "hiredis-0.14.1": ("BSD-3-Clause", "ext/hiredis-0.14.1/COPYING"),
    "hiredis-1.0.2": ("BSD-3-Clause", "ext/hiredis-1.0.2/COPYING"),
    "http-parser": ("MIT", "per-file license text in http_parser.c/.h"),
    "inja": ("MIT", "ext/inja/LICENSE"),
    "libnatpmp": ("BSD-3-Clause", "ext/libnatpmp/LICENSE"),
    "libpqxx-7.7.3": ("BSD-3-Clause", "ext/libpqxx-7.7.3/COPYING"),
    "miniupnpc": ("BSD-3-Clause", "ext/miniupnpc/LICENSE"),
    "nlohmann": ("MIT", "ext/nlohmann/LICENSE.MIT"),
    "prometheus-cpp-lite-1.0": ("MIT", "ext/prometheus-cpp-lite-1.0/LICENSE"),
    "redis-plus-plus-1.1.1": ("Apache-2.0", "ext/redis-plus-plus-1.1.1/LICENSE"),
    "redis-plus-plus-1.3.3": ("Apache-2.0", "ext/redis-plus-plus-1.3.3/LICENSE"),
    "x64-salsa2012-asm": ("LicenseRef-Public-Domain", "ext/x64-salsa2012-asm/README.md"),
}

EXPLICIT_MARKERS = (
    "GPL-",
    "LGPL-",
    "MIT",
    "BSD-",
    "MS-PL",
    "MPL-",
    "public-domain",
    "Public-Domain",
    "X11",
    "JSON",
    "ISC",
)


def git_files() -> list[tuple[str, str]]:
    raw = subprocess.check_output(["git", "ls-files", "-s", "-z"])
    result = []
    for item in raw.decode("utf-8", "surrogateescape").split("\0"):
        if not item:
            continue
        metadata, path = item.split("\t", 1)
        mode = metadata.split()[0]
        result.append((path, mode))
    return result


def scan_index(scan_path: Path) -> dict[str, dict]:
    data = json.loads(scan_path.read_text(encoding="utf-8"))
    index = {}
    for item in data["files"]:
        if item.get("type") != "file":
            continue
        path = item["path"]
        marker = "/zt-tracked-audit."
        if marker in path:
            path = path.split("/", 3)[-1]
        elif "/" in path:
            path = path.split("/", 1)[-1]
        index[path] = item
    return index


def content_metadata(path: Path, mode: str) -> tuple[int, str]:
    if mode == "120000":
        payload = os.readlink(path).encode("utf-8", "surrogateescape")
    else:
        payload = path.read_bytes()
    return len(payload), hashlib.sha256(payload).hexdigest()


def classify(path: str, scan: dict | None) -> tuple[str, str, str, str]:
    direct = ""
    if scan:
        direct = scan.get("detected_license_expression_spdx") or ""
    is_code = bool(scan and (scan.get("is_source") or scan.get("is_script")))

    if "proprietary-license" in direct and not path.lower().endswith((".md", ".txt", "authors", "copying")):
        return direct, "NOASSERTION", "possible proprietary material detected", "review"

    if path.startswith("ext/"):
        parts = path.split("/")
        package = parts[1] if len(parts) > 1 else ""
        inherited = EXT_SCOPES.get(package)
        if inherited:
            effective, basis = inherited
            if is_code and direct and any(marker in direct for marker in EXPLICIT_MARKERS):
                if "FSFULL" in direct or "Autoconf-exception" in direct:
                    return direct, direct, "direct ScanCode detection", "medium"
                if effective not in direct and not (
                    effective == "LicenseRef-Public-Domain" and "public-domain" in direct
                ):
                    return direct, direct, "direct per-file terms override package default", "medium"
            return direct or "NONE", effective, basis, "high"
        return direct or "NONE", "NOASSERTION", "no applicable license located for this ext/ subtree", "review"

    if path.startswith("windows/TapDriver6/"):
        return direct or "NONE", "GPL-2.0-only", "GPLv2 file headers and driver subtree context", "high"

    if path.startswith("attic/historic/anode/"):
        return direct or "NONE", "GPL-3.0-or-later", "attic/historic/anode/LICENSE.txt and file headers", "high"

    if is_code and direct and any(marker in direct for marker in EXPLICIT_MARKERS):
        return direct, direct, "direct ScanCode detection", "high"

    return direct or "NONE", ROOT_EFFECTIVE, "root LICENSE.txt and COPYING", "high"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    root = Path.cwd()
    scans = scan_index(args.scan)
    rows = []
    for path, mode in git_files():
        size, sha256 = content_metadata(root / path, mode)
        scan = scans.get(path)
        direct, effective, basis, confidence = classify(path, scan)
        rows.append(
            {
                "path": path,
                "git_mode": mode,
                "size_bytes": size,
                "sha256": sha256,
                "file_type": (scan or {}).get(
                    "file_type", "symbolic link" if mode == "120000" else "unscanned Git metadata"
                ),
                "language": (scan or {}).get("programming_language") or "",
                "is_binary": (scan or {}).get("is_binary", mode == "120000"),
                "scan_status": "scanned" if scan else "scope-only",
                "direct_detection": direct,
                "effective_license": effective,
                "basis": basis,
                "confidence": confidence,
                "scan_errors": "; ".join((scan or {}).get("scan_errors", [])),
            }
        )

    args.csv.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    licenses = Counter(row["effective_license"] for row in rows)
    confidence = Counter(row["confidence"] for row in rows)
    review = [row for row in rows if row["confidence"] == "review"]
    errors = [row for row in rows if row["scan_errors"]]
    scanned = sum(row["scan_status"] == "scanned" for row in rows)
    lines = [
        "# Auditoría de licencias de ZeroTier One 1.14.2",
        "",
        f"- Commit auditado: `{subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()}`",
        f"- Archivos rastreados: **{len(rows)}**",
        f"- Archivos inspeccionados directamente por ScanCode: **{scanned}**",
        f"- Metadatos o enlaces clasificados únicamente por alcance: **{len(rows) - scanned}**",
        f"- Archivos que requieren revisión manual: **{len(review)}**",
        f"- Errores del escáner: **{len(errors)}**",
        "- Herramienta de detección: ScanCode Toolkit 32.5.0, umbral 70",
        "",
        "## Resultado por licencia efectiva",
        "",
        "| Archivos | Licencia o conclusión |",
        "|---:|---|",
    ]
    for license_name, count in licenses.most_common():
        lines.append(f"| {count} | `{license_name}` |")
    lines += [
        "",
        "## Nivel de confianza",
        "",
        "| Archivos | Nivel |",
        "|---:|---|",
    ]
    for level, count in confidence.most_common():
        lines.append(f"| {count} | `{level}` |")
    lines += [
        "",
        "## Casos que requieren revisión",
        "",
        "Estos archivos están en subárboles externos para los que no se encontró una",
        "declaración de licencia aplicable. No deben copiarse al port hasta aclarar su",
        "procedencia o reemplazarlos.",
        "",
    ]
    for row in review:
        lines.append(f"- `{row['path']}`")
    lines += [
        "",
        "## Criterio aplicado",
        "",
        "La detección directa identifica textos o avisos dentro del archivo. Cuando un",
        "archivo carece de aviso, se aplica solamente una licencia de paquete respaldada",
        "por un LICENSE/COPYING o una declaración inequívoca. El resto del árbol propio",
        "se clasifica bajo la BSL 1.1 del repositorio, cuya Change Date fue 2026-01-01 y",
        "cuya Change License declarada es Apache-2.0. Esta clasificación no resuelve la",
        "ambigüedad jurídica de que el campo Licensed Work mencione la versión 1.4.4.",
        "",
        "El CSV es el resultado canónico archivo por archivo.",
    ]
    args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} rows; {len(review)} require review; {len(errors)} scan errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
