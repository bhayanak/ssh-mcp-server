"""Tests for the certificate manager (Phase 3)."""

from __future__ import annotations

import time

import pytest

from ssh_mcp.certs import CertManager, IssuedCert


@pytest.fixture()
def cert_mgr(tmp_path):
    return CertManager(tmp_path / "certs", default_ttl=300, max_ttl=3600)


# ------------------------------------------------------------------
# CA initialisation
# ------------------------------------------------------------------


class TestCABootstrap:
    def test_ca_creates_key_and_cert(self, cert_mgr, tmp_path):
        ca_dir = tmp_path / "certs"
        assert (ca_dir / "ca_key.pem").exists()
        assert (ca_dir / "ca_cert.pem").exists()

    def test_ca_reloads_existing(self, tmp_path):
        ca_dir = tmp_path / "certs"
        mgr1 = CertManager(ca_dir, default_ttl=300, max_ttl=3600)
        pem1 = mgr1.get_ca_public_key_pem()
        mgr2 = CertManager(ca_dir, default_ttl=300, max_ttl=3600)
        pem2 = mgr2.get_ca_public_key_pem()
        assert pem1 == pem2, "Reloaded CA should have the same public key"


# ------------------------------------------------------------------
# Certificate issuance
# ------------------------------------------------------------------


class TestIssuance:
    def test_issue_creates_cert(self, cert_mgr):
        issued = cert_mgr.issue_cert("alice")
        assert isinstance(issued, IssuedCert)
        assert issued.user_id == "alice"
        assert issued.cert_id
        assert issued.fingerprint
        assert not issued.revoked

    def test_issue_uses_default_ttl(self, cert_mgr):
        issued = cert_mgr.issue_cert("bob")
        assert issued.expires_at - issued.issued_at == pytest.approx(300, abs=2)

    def test_issue_custom_ttl(self, cert_mgr):
        issued = cert_mgr.issue_cert("charlie", ttl_seconds=600)
        assert issued.expires_at - issued.issued_at == pytest.approx(600, abs=2)

    def test_issue_rejects_excessive_ttl(self, cert_mgr):
        with pytest.raises(ValueError, match="exceeds max"):
            cert_mgr.issue_cert("dave", ttl_seconds=99999)

    def test_issue_writes_pem_file(self, cert_mgr, tmp_path):
        issued = cert_mgr.issue_cert("eve")
        pem_path = tmp_path / "certs" / f"{issued.cert_id}.pem"
        assert pem_path.exists()
        content = pem_path.read_text()
        assert "BEGIN CERTIFICATE" in content
        assert "BEGIN" in content  # key also present

    def test_issue_with_principals(self, cert_mgr):
        issued = cert_mgr.issue_cert("frank", principals=["frank", "root"])
        assert issued.principals == ["frank", "root"]

    def test_issue_default_principals(self, cert_mgr):
        issued = cert_mgr.issue_cert("grace")
        assert issued.principals == ["grace"]


# ------------------------------------------------------------------
# Revocation
# ------------------------------------------------------------------


class TestRevocation:
    def test_revoke_cert(self, cert_mgr):
        issued = cert_mgr.issue_cert("alice")
        revoked = cert_mgr.revoke_cert(issued.cert_id, "compromised")
        assert revoked.revoked
        assert revoked.revoke_reason == "compromised"
        assert revoked.revoked_at is not None

    def test_revoke_removes_pem(self, cert_mgr, tmp_path):
        issued = cert_mgr.issue_cert("bob")
        pem_path = tmp_path / "certs" / f"{issued.cert_id}.pem"
        assert pem_path.exists()
        cert_mgr.revoke_cert(issued.cert_id)
        assert not pem_path.exists()

    def test_revoke_unknown_raises(self, cert_mgr):
        with pytest.raises(ValueError, match="Unknown cert_id"):
            cert_mgr.revoke_cert("nonexistent")

    def test_revoke_already_revoked_raises(self, cert_mgr):
        issued = cert_mgr.issue_cert("charlie")
        cert_mgr.revoke_cert(issued.cert_id, "first")
        with pytest.raises(ValueError, match="already revoked"):
            cert_mgr.revoke_cert(issued.cert_id, "second")

    def test_revoked_cert_is_not_valid(self, cert_mgr):
        issued = cert_mgr.issue_cert("dave")
        assert cert_mgr.is_valid(issued.cert_id)
        cert_mgr.revoke_cert(issued.cert_id, "test")
        assert not cert_mgr.is_valid(issued.cert_id)

    def test_is_revoked_by_serial(self, cert_mgr):
        issued = cert_mgr.issue_cert("eve")
        assert not cert_mgr.is_revoked(serial=issued.serial)
        cert_mgr.revoke_cert(issued.cert_id, "test")
        assert cert_mgr.is_revoked(serial=issued.serial)

    def test_unknown_cert_treated_as_revoked(self, cert_mgr):
        assert cert_mgr.is_revoked(cert_id="nonexistent")


# ------------------------------------------------------------------
# Expiry
# ------------------------------------------------------------------


class TestExpiry:
    def test_not_expired_within_ttl(self, cert_mgr):
        issued = cert_mgr.issue_cert("alice", ttl_seconds=300)
        assert not cert_mgr.is_expired(issued.cert_id)

    def test_expired_cert(self, tmp_path):
        mgr = CertManager(tmp_path / "certs", default_ttl=1, max_ttl=5)
        issued = mgr.issue_cert("bob", ttl_seconds=1)
        # Manually backdate the registry entry
        mgr._registry[issued.cert_id]["expires_at"] = time.time() - 10
        assert mgr.is_expired(issued.cert_id)
        assert not mgr.is_valid(issued.cert_id)


# ------------------------------------------------------------------
# Listing
# ------------------------------------------------------------------


class TestListing:
    def test_list_all_certs(self, cert_mgr):
        cert_mgr.issue_cert("alice")
        cert_mgr.issue_cert("bob")
        certs = cert_mgr.list_certs()
        assert len(certs) == 2

    def test_list_by_user(self, cert_mgr):
        cert_mgr.issue_cert("alice")
        cert_mgr.issue_cert("bob")
        cert_mgr.issue_cert("alice")
        assert len(cert_mgr.list_certs(user_id="alice")) == 2
        assert len(cert_mgr.list_certs(user_id="bob")) == 1

    def test_ca_public_key_pem(self, cert_mgr):
        pem = cert_mgr.get_ca_public_key_pem()
        assert "BEGIN CERTIFICATE" in pem


# ------------------------------------------------------------------
# Persistence across reloads
# ------------------------------------------------------------------


class TestPersistence:
    def test_registry_survives_reload(self, tmp_path):
        ca_dir = tmp_path / "certs"
        mgr1 = CertManager(ca_dir, default_ttl=300, max_ttl=3600)
        issued = mgr1.issue_cert("alice")
        mgr1.revoke_cert(issued.cert_id, "test")

        mgr2 = CertManager(ca_dir, default_ttl=300, max_ttl=3600)
        assert mgr2.is_revoked(cert_id=issued.cert_id)
        assert len(mgr2.list_certs()) == 1

    def test_revocation_list_survives_reload(self, tmp_path):
        ca_dir = tmp_path / "certs"
        mgr1 = CertManager(ca_dir, default_ttl=300, max_ttl=3600)
        issued = mgr1.issue_cert("bob")
        mgr1.revoke_cert(issued.cert_id, "test")

        mgr2 = CertManager(ca_dir, default_ttl=300, max_ttl=3600)
        assert mgr2.is_revoked(serial=issued.serial)
