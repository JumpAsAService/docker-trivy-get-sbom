#!/usr/bin/env python3
"""Genera l'SBOM delle immagini di un container registry e la scansiona con Trivy.

Configurabile via variabili d'ambiente o argomenti da riga di comando
(gli argomenti hanno la precedenza). Usa solo la standard library.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SBOM_EXTENSIONS = {"cyclonedx": "cdx.json", "spdx-json": "spdx.json"}
REPORT_EXTENSIONS = {"json": "json", "sarif": "sarif", "table": "txt"}


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def _log(level: str, color: str, message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"\033[1;{color}m[{stamp}] {level}\033[0m {message}", file=sys.stderr, flush=True)


def info(message: str) -> None:
    _log("INFO", "34", message)


def warn(message: str) -> None:
    _log("WARN", "33", message)


def error(message: str) -> None:
    _log("ERRORE", "31", message)


class ConfigError(Exception):
    """Configurazione non valida: interrompe l'esecuzione con exit code 2."""


# --------------------------------------------------------------------------- #
# Configurazione
# --------------------------------------------------------------------------- #
def env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    registry_host: str = ""
    username: str = ""
    password: str = ""
    token: str = ""
    insecure: bool = False
    ca_cert_file: str = ""

    images: list[str] = field(default_factory=list)
    harbor_project: str = ""
    discover_catalog: bool = False
    tag_limit: int = 1

    sbom_format: str = "cyclonedx"
    scan_format: str = "table"
    severity: str = "HIGH,CRITICAL"
    ignore_unfixed: bool = False
    embed_vulns: bool = False
    skip_db_update: bool = False
    exit_code_on_findings: int = 0

    output_dir: Path = Path("/scratch/reports")
    sbom_dir: Path = Path("/scratch/sbom")

    @classmethod
    def from_env(cls) -> "Config":
        raw_images = os.getenv("IMAGES", "")
        images = [i for i in raw_images.replace(",", " ").split() if i]
        return cls(
            registry_host=os.getenv("REGISTRY_HOST", "").strip().rstrip("/"),
            username=os.getenv("REGISTRY_USER", ""),
            password=os.getenv("REGISTRY_PASSWORD", ""),
            token=os.getenv("REGISTRY_TOKEN", ""),
            insecure=env_bool("REGISTRY_INSECURE"),
            ca_cert_file=os.getenv("CA_CERT_FILE", ""),
            images=images,
            harbor_project=os.getenv("HARBOR_PROJECT", ""),
            discover_catalog=env_bool("DISCOVER_CATALOG"),
            tag_limit=int(os.getenv("TAG_LIMIT", "1")),
            sbom_format=os.getenv("SBOM_FORMAT", "cyclonedx"),
            scan_format=os.getenv("SCAN_FORMAT", "table"),
            severity=os.getenv("SEVERITY", "HIGH,CRITICAL"),
            ignore_unfixed=env_bool("IGNORE_UNFIXED"),
            embed_vulns=env_bool("EMBED_VULNS"),
            skip_db_update=env_bool("SKIP_DB_UPDATE"),
            exit_code_on_findings=int(os.getenv("EXIT_CODE_ON_FINDINGS", "0")),
            output_dir=Path(os.getenv("OUTPUT_DIR", "/scratch/reports")),
            sbom_dir=Path(os.getenv("SBOM_DIR", "/scratch/sbom")),
        )

    def validate(self) -> None:
        if self.sbom_format not in SBOM_EXTENSIONS:
            raise ConfigError(
                f"SBOM_FORMAT non supportato: {self.sbom_format} "
                f"(scegli tra {', '.join(SBOM_EXTENSIONS)})"
            )
        if self.scan_format not in REPORT_EXTENSIONS:
            raise ConfigError(
                f"SCAN_FORMAT non supportato: {self.scan_format} "
                f"(scegli tra {', '.join(REPORT_EXTENSIONS)})"
            )
        if self.embed_vulns and self.sbom_format != "cyclonedx":
            raise ConfigError(
                "EMBED_VULNS richiede SBOM_FORMAT=cyclonedx: lo standard SPDX non "
                "prevede un campo per le vulnerabilità"
            )
        if self.username and not self.password:
            raise ConfigError("REGISTRY_PASSWORD mancante (oppure usa REGISTRY_TOKEN)")
        if not (self.images or self.harbor_project or self.discover_catalog):
            raise ConfigError(
                "Serve almeno una sorgente: IMAGES, HARBOR_PROJECT o DISCOVER_CATALOG=true"
            )
        if (self.harbor_project or self.discover_catalog) and not self.registry_host:
            raise ConfigError("REGISTRY_HOST è obbligatorio per la discovery automatica")

    @property
    def auth_mode(self) -> str:
        if self.token:
            return "bearer token"
        if self.username:
            return f"basic ({self.username})"
        return "anonimo"


# --------------------------------------------------------------------------- #
# Credenziali
# --------------------------------------------------------------------------- #
def apply_credentials(cfg: Config) -> None:
    """Trivy legge queste variabili nativamente: nessun docker login necessario."""
    if cfg.token:
        os.environ["TRIVY_REGISTRY_TOKEN"] = cfg.token
    elif cfg.username:
        os.environ["TRIVY_USERNAME"] = cfg.username
        os.environ["TRIVY_PASSWORD"] = cfg.password
    if cfg.insecure:
        os.environ["TRIVY_INSECURE"] = "true"

    if cfg.ca_cert_file:
        source = Path(cfg.ca_cert_file)
        if not source.is_file():
            raise ConfigError(f"CA_CERT_FILE non trovato: {source}")
        # Niente update-ca-certificates: richiede root e un filesystem scrivibile.
        # Go (trivy) e Python leggono entrambi SSL_CERT_FILE.
        os.environ["SSL_CERT_FILE"] = str(source)
        info(f"CA custom attiva via SSL_CERT_FILE: {source}")


# --------------------------------------------------------------------------- #
# Client API del registry (solo per la discovery)
# --------------------------------------------------------------------------- #
class RegistryClient:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.base = f"https://{cfg.registry_host}"
        self.ssl_context = ssl.create_default_context()
        if cfg.insecure:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        elif cfg.ca_cert_file:
            self.ssl_context.load_verify_locations(cfg.ca_cert_file)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.cfg.token:
            headers["Authorization"] = f"Bearer {self.cfg.token}"
        elif self.cfg.username:
            raw = f"{self.cfg.username}:{self.cfg.password}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        return headers

    def get_json(self, path: str):
        url = urllib.parse.urljoin(self.base, path)
        request = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(request, context=self.ssl_context, timeout=30) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raise ConfigError(f"HTTP {exc.code} su {url}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise ConfigError(f"Connessione fallita a {url}: {exc.reason}") from exc

    def harbor_images(self, project: str, tag_limit: int) -> list[str]:
        """Repository e tag più recenti di un progetto Harbor (API v2.0)."""
        repositories = self.get_json(
            f"/api/v2.0/projects/{urllib.parse.quote(project)}/repositories?page_size=100"
        )
        targets: list[str] = []
        for repo in repositories:
            full_name = repo["name"]                      # "progetto/repo"
            short_name = full_name[len(project) + 1 :]    # "repo" (può contenere /)
            # Harbor vuole lo slash del nome doppiamente url-encoded
            encoded = urllib.parse.quote(short_name, safe="").replace("%2F", "%252F")
            artifacts = self.get_json(
                f"/api/v2.0/projects/{urllib.parse.quote(project)}/repositories/"
                f"{encoded}/artifacts?page_size={tag_limit}&sort=-push_time"
            )
            for artifact in artifacts:
                for tag in artifact.get("tags") or []:
                    targets.append(f"{self.cfg.registry_host}/{full_name}:{tag['name']}")
        return targets

    def catalog_images(self, tag_limit: int) -> list[str]:
        """Docker Registry API v2. Su Harbor /v2/_catalog richiede un utente admin."""
        catalog = self.get_json("/v2/_catalog?n=1000")
        targets: list[str] = []
        for repo in catalog.get("repositories", []):
            tags = self.get_json(f"/v2/{repo}/tags/list").get("tags") or []
            for tag in tags[-tag_limit:]:
                targets.append(f"{self.cfg.registry_host}/{repo}:{tag}")
        return targets


def resolve_targets(cfg: Config) -> list[str]:
    if cfg.images:
        return [
            image if not cfg.registry_host or image.startswith(f"{cfg.registry_host}/")
            else f"{cfg.registry_host}/{image}"
            for image in cfg.images
        ]

    client = RegistryClient(cfg)
    if cfg.harbor_project:
        info(f"Discovery via API Harbor sul progetto '{cfg.harbor_project}'")
        return client.harbor_images(cfg.harbor_project, cfg.tag_limit)

    info("Discovery via Docker Registry API v2 (/v2/_catalog)")
    return client.catalog_images(cfg.tag_limit)


# --------------------------------------------------------------------------- #
# Trivy
# --------------------------------------------------------------------------- #
def run_trivy(args: list[str]) -> int:
    return subprocess.run(["trivy", *args], check=False).returncode


def update_database(cfg: Config) -> list[str]:
    if cfg.skip_db_update:
        info("Aggiornamento DB saltato (modalità air-gapped)")
        return ["--skip-db-update", "--skip-java-db-update"]
    info("Aggiorno il database delle vulnerabilità")
    if run_trivy(["image", "--download-db-only"]) != 0:
        warn("Download del DB fallito, procedo con la cache esistente")
    return []


def slugify(reference: str) -> str:
    return "".join("_" if c in "/:@" else c for c in reference)


def generate_sbom(cfg: Config, reference: str, db_flags: list[str]) -> Path | None:
    destination = cfg.sbom_dir / f"{slugify(reference)}.{SBOM_EXTENSIONS[cfg.sbom_format]}"
    info(f"→ {reference}: genero l'SBOM ({cfg.sbom_format})")
    code = run_trivy(
        ["image", *db_flags, "--format", cfg.sbom_format, "--output", str(destination), reference]
    )
    if code != 0:
        warn(f"   generazione SBOM fallita (exit {code})")
        return None
    return destination


def count_embedded_vulns(sbom_path: Path) -> int:
    """Conta le vulnerabilità nell'array top-level di un CycloneDX."""
    try:
        document = json.loads(sbom_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        warn(f"   SBOM illeggibile ({exc}), conteggio non disponibile")
        return 0
    return len(document.get("vulnerabilities") or [])


def generate_sbom_with_vulns(cfg: Config, reference: str, db_flags: list[str]) -> int:
    """Passaggio unico: SBOM CycloneDX con le vulnerabilità già incorporate.

    Restituisce 1 se ci sono findings, 0 se pulito, 2 se la generazione fallisce.
    """
    destination = cfg.sbom_dir / f"{slugify(reference)}.{SBOM_EXTENSIONS[cfg.sbom_format]}"
    args = [
        "image",
        *db_flags,
        "--format", cfg.sbom_format,
        "--scanners", "vuln",
        "--severity", cfg.severity,
        "--output", str(destination),
    ]
    if cfg.ignore_unfixed:
        args.append("--ignore-unfixed")
    args.append(reference)

    info(f"→ {reference}: genero l'SBOM con le vulnerabilità incorporate")
    if run_trivy(args) != 0:
        warn("   generazione fallita")
        return 2

    found = count_embedded_vulns(destination)
    if found:
        warn(f"   {found} vulnerabilità {cfg.severity} incorporate → {destination}")
        return 1
    info(f"   nessuna vulnerabilità {cfg.severity} → {destination}")
    return 0


def scan_sbom(cfg: Config, reference: str, sbom_path: Path, db_flags: list[str]) -> int:
    report = cfg.output_dir / f"{slugify(reference)}.{REPORT_EXTENSIONS[cfg.scan_format]}"
    flags = ["--severity", cfg.severity, "--format", cfg.scan_format]
    if cfg.ignore_unfixed:
        flags.append("--ignore-unfixed")

    info(f"→ {reference}: scansiono l'SBOM")
    code = run_trivy(
        ["sbom", *db_flags, *flags, "--exit-code", "1", "--output", str(report), str(sbom_path)]
    )
    if code == 1:
        warn(f"   trovate vulnerabilità → {report}")
        if cfg.scan_format == "table" and report.exists():
            print(report.read_text())
    elif code == 0:
        info(f"   nessuna vulnerabilità {cfg.severity}")
    else:
        warn(f"   scan fallito (exit {code})")
    return code


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str], cfg: Config) -> Config:
    parser = argparse.ArgumentParser(
        prog="scanner", description="Genera e scansiona l'SBOM di immagini di un registry."
    )
    parser.add_argument("--registry-host", default=cfg.registry_host)
    parser.add_argument("--image", action="append", dest="images", default=None)
    parser.add_argument("--harbor-project", default=cfg.harbor_project)
    parser.add_argument("--tag-limit", type=int, default=cfg.tag_limit)
    parser.add_argument("--sbom-format", choices=sorted(SBOM_EXTENSIONS), default=cfg.sbom_format)
    parser.add_argument("--scan-format", choices=sorted(REPORT_EXTENSIONS), default=cfg.scan_format)
    parser.add_argument("--severity", default=cfg.severity)
    parser.add_argument("--ignore-unfixed", action="store_true", default=cfg.ignore_unfixed)
    parser.add_argument("--embed-vulns", action="store_true", default=cfg.embed_vulns)
    parser.add_argument("--output-dir", type=Path, default=cfg.output_dir)

    args = parser.parse_args(argv)
    cfg.registry_host = args.registry_host.rstrip("/")
    if args.images:
        cfg.images = args.images
    cfg.harbor_project = args.harbor_project
    cfg.tag_limit = args.tag_limit
    cfg.sbom_format = args.sbom_format
    cfg.scan_format = args.scan_format
    cfg.severity = args.severity
    cfg.ignore_unfixed = args.ignore_unfixed
    cfg.embed_vulns = args.embed_vulns
    cfg.output_dir = args.output_dir
    return cfg


def main(argv: list[str]) -> int:
    # Escape hatch: un sottocomando trivy (parola, non flag) viene girato a trivy.
    # Gli argomenti che iniziano con "-" appartengono sempre allo scanner, così un
    # flag sbagliato dà un errore chiaro invece di finire a trivy.
    if argv and argv[0] != "scan" and not argv[0].startswith("-"):
        return run_trivy(argv)
    if argv and argv[0] == "scan":
        argv = argv[1:]

    cfg = parse_args(argv, Config.from_env())
    cfg.validate()

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    cfg.sbom_dir.mkdir(parents=True, exist_ok=True)

    apply_credentials(cfg)
    info(f"Autenticazione: {cfg.auth_mode} su {cfg.registry_host or '<registry di default>'}")

    targets = resolve_targets(cfg)
    if not targets:
        raise ConfigError("Nessuna immagine da analizzare")
    info(f"Immagini da analizzare: {len(targets)}")

    db_flags = update_database(cfg)
    with_findings, failed = 0, 0

    for reference in targets:
        if cfg.embed_vulns:
            code = generate_sbom_with_vulns(cfg, reference, db_flags)
        else:
            sbom_path = generate_sbom(cfg, reference, db_flags)
            if sbom_path is None:
                failed += 1
                continue
            code = scan_sbom(cfg, reference, sbom_path, db_flags)

        if code == 1:
            with_findings += 1
        elif code != 0:
            failed += 1

    info(
        f"Fatto. Immagini: {len(targets)} | con findings: {with_findings} | errori: {failed}"
    )
    if cfg.embed_vulns:
        info(f"SBOM con vulnerabilità incorporate in {cfg.sbom_dir}")
    else:
        info(f"SBOM in {cfg.sbom_dir}, report in {cfg.output_dir}")

    if failed:
        return 3
    if with_findings:
        return cfg.exit_code_on_findings
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ConfigError as exc:
        error(str(exc))
        sys.exit(2)
    except KeyboardInterrupt:
        error("Interrotto")
        sys.exit(130)