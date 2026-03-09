"""Short-lived SSH certificate manager.

Provides a local SSH CA that issues ephemeral user certificates with
tight TTLs, and maintains a revocation list.  In production this would
delegate to HashiCorp Vault or a dedicated CA service — this module
implements the same interface using the `cryptography` library so the
flow can be tested end-to-end without external infrastructure.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.x509 import (
    CertificateBuilder,
    Name,
    NameAttribute,
    random_serial_number,
)
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class IssuedCert:
    cert_id: str
    user_id: str
    serial: int
    issued_at: float
    expires_at: float
    principals: list[str]
    fingerprint: str
    revoked: bool = False
    revoked_at: float | None = None
    revoke_reason: str = ""


# ---------------------------------------------------------------------------
# Certificate Manager
# ---------------------------------------------------------------------------


class CertManager:
    """Manages a local SSH CA for issuing short-lived certificates."""

    def __init__(
        self,
        data_dir: Path,
        default_ttl: int = 86400,
        max_ttl: int = 86400 * 7,
    ) -> None:
        self._data_dir = data_dir
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl

        self._ca_key_path = self._data_dir / "ca_key.pem"
        self._ca_cert_path = self._data_dir / "ca_cert.pem"
        self._registry_path = self._data_dir / "cert_registry.json"
        self._revocation_path = self._data_dir / "revocation_list.json"

        self._ca_key: PrivateKeyTypes | None = None
        self._ca_cert: x509.Certificate | None = None

        self._registry: dict[str, dict] = {}
        self._revoked_serials: set[int] = set()

        self._load_or_create_ca()
        self._load_registry()
        self._load_revocation_list()

    # ------------------------------------------------------------------
    # CA bootstrap
    # ------------------------------------------------------------------

    def _load_or_create_ca(self) -> None:
        if self._ca_key_path.exists() and self._ca_cert_path.exists():
            self._ca_key = serialization.load_pem_private_key(
                self._ca_key_path.read_bytes(), password=None
            )
            self._ca_cert = x509.load_pem_x509_certificate(
                self._ca_cert_path.read_bytes()
            )
            return

        # Generate a new EC P-256 CA key pair
        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = Name([
            NameAttribute(NameOID.COMMON_NAME, "ssh-mcp-ca"),
            NameAttribute(NameOID.ORGANIZATION_NAME, "ssh-mcp-server"),
        ])
        self._ca_cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=3650)
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        # Persist CA material
        self._ca_key_path.write_bytes(
            self._ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self._ca_cert_path.write_bytes(
            self._ca_cert.public_bytes(serialization.Encoding.PEM)
        )

    # ------------------------------------------------------------------
    # Registry persistence
    # ------------------------------------------------------------------

    def _load_registry(self) -> None:
        if self._registry_path.exists():
            data = json.loads(self._registry_path.read_text(encoding="utf-8"))
            self._registry = {e["cert_id"]: e for e in data}

    def _save_registry(self) -> None:
        self._registry_path.write_text(
            json.dumps(list(self._registry.values()), indent=2),
            encoding="utf-8",
        )

    def _load_revocation_list(self) -> None:
        if self._revocation_path.exists():
            data = json.loads(self._revocation_path.read_text(encoding="utf-8"))
            self._revoked_serials = set(data.get("serials", []))

    def _save_revocation_list(self) -> None:
        self._revocation_path.write_text(
            json.dumps({"serials": sorted(self._revoked_serials)}),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Issue certificate
    # ------------------------------------------------------------------

    def issue_cert(
        self,
        user_id: str,
        principals: list[str] | None = None,
        ttl_seconds: int = 0,
    ) -> IssuedCert:
        """Issue a short-lived X.509 certificate for the given user.

        Returns an IssuedCert with metadata.  The actual PEM cert is
        written to the data directory as ``{cert_id}.pem``.
        """
        if self._ca_key is None or self._ca_cert is None:
            raise RuntimeError("CA not initialised")

        effective_ttl = ttl_seconds if ttl_seconds > 0 else self._default_ttl
        if effective_ttl > self._max_ttl:
            raise ValueError(
                f"Requested TTL {effective_ttl}s exceeds max {self._max_ttl}s"
            )

        # Generate an ephemeral key for the user cert
        user_key = ec.generate_private_key(ec.SECP256R1())
        serial = random_serial_number()
        now = datetime.datetime.now(datetime.timezone.utc)

        subject = Name([
            NameAttribute(NameOID.COMMON_NAME, user_id),
        ])

        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(seconds=effective_ttl))
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_id = uuid.uuid4().hex[:12]
        fingerprint = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()

        # Write cert + key to data dir
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = user_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        (self._data_dir / f"{cert_id}.pem").write_bytes(cert_pem + key_pem)

        issued = IssuedCert(
            cert_id=cert_id,
            user_id=user_id,
            serial=serial,
            issued_at=time.time(),
            expires_at=time.time() + effective_ttl,
            principals=principals or [user_id],
            fingerprint=fingerprint,
        )

        self._registry[cert_id] = {
            "cert_id": cert_id,
            "user_id": user_id,
            "serial": serial,
            "issued_at": issued.issued_at,
            "expires_at": issued.expires_at,
            "principals": issued.principals,
            "fingerprint": fingerprint,
            "revoked": False,
        }
        self._save_registry()

        return issued

    # ------------------------------------------------------------------
    # Revoke certificate
    # ------------------------------------------------------------------

    def revoke_cert(self, cert_id: str, reason: str = "") -> IssuedCert:
        """Revoke a certificate by cert_id."""
        entry = self._registry.get(cert_id)
        if entry is None:
            raise ValueError(f"Unknown cert_id: {cert_id}")

        if entry.get("revoked"):
            raise ValueError(f"Certificate {cert_id} is already revoked")

        entry["revoked"] = True
        entry["revoked_at"] = time.time()
        entry["revoke_reason"] = reason

        self._revoked_serials.add(entry["serial"])
        self._save_revocation_list()
        self._save_registry()

        # Remove the PEM file
        pem_path = self._data_dir / f"{cert_id}.pem"
        if pem_path.exists():
            pem_path.unlink()

        return IssuedCert(**{k: v for k, v in entry.items() if k != "revoke_reason"},
                          revoke_reason=reason)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def is_revoked(self, cert_id: str | None = None, serial: int | None = None) -> bool:
        """Check if a cert is revoked by cert_id or serial number."""
        if serial is not None:
            return serial in self._revoked_serials

        if cert_id is not None:
            entry = self._registry.get(cert_id)
            if entry is None:
                return True  # unknown certs treated as revoked
            return bool(entry.get("revoked"))

        raise ValueError("Provide cert_id or serial")

    def is_expired(self, cert_id: str) -> bool:
        """Check if a cert has passed its expiry time."""
        entry = self._registry.get(cert_id)
        if entry is None:
            return True
        return time.time() > entry["expires_at"]

    def is_valid(self, cert_id: str) -> bool:
        """A cert is valid if it is not expired and not revoked."""
        return not self.is_expired(cert_id) and not self.is_revoked(cert_id=cert_id)

    def list_certs(self, user_id: str | None = None) -> list[IssuedCert]:
        """List issued certificates, optionally filtered by user."""
        results = []
        for entry in self._registry.values():
            if user_id and entry["user_id"] != user_id:
                continue
            results.append(
                IssuedCert(
                    cert_id=entry["cert_id"],
                    user_id=entry["user_id"],
                    serial=entry["serial"],
                    issued_at=entry["issued_at"],
                    expires_at=entry["expires_at"],
                    principals=entry["principals"],
                    fingerprint=entry["fingerprint"],
                    revoked=entry.get("revoked", False),
                    revoked_at=entry.get("revoked_at"),
                    revoke_reason=entry.get("revoke_reason", ""),
                )
            )
        return results

    def get_ca_public_key_pem(self) -> str:
        """Return the CA public certificate PEM for trust anchoring."""
        if self._ca_cert is None:
            raise RuntimeError("CA not initialised")
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()
