"""Unit tests for lab profile validation."""

import pytest
from pydantic import ValidationError

from mauberesec.docker.labs import DEFAULT_CPUS, DEFAULT_MEMORY, LabProfile, LabService


def service(name: str = "web", image: str = "nginx:1.27-alpine") -> LabService:
    return LabService(name=name, image=image)


def test_valid_profile():
    profile = LabProfile(name="demo", subnet_cidr="10.66.7.0/24", services=(service(),))
    assert profile.network_name() == "msai-lab-demo-net"
    assert profile.container_name(service()) == "msai-lab-demo-web"


def test_public_subnet_rejected():
    with pytest.raises(ValidationError, match="private"):
        LabProfile(name="bad", subnet_cidr="8.8.8.0/24", services=(service(),))


def test_oversized_subnet_rejected():
    with pytest.raises(ValidationError, match="/24 or smaller"):
        LabProfile(name="bad", subnet_cidr="10.0.0.0/16", services=(service(),))


def test_invalid_cidr_rejected():
    with pytest.raises(ValidationError, match="Invalid CIDR"):
        LabProfile(name="bad", subnet_cidr="not-a-cidr", services=(service(),))


def test_profile_requires_service():
    with pytest.raises(ValidationError):
        LabProfile(name="empty", subnet_cidr="10.66.8.0/24", services=())


def test_defaults_hardened():
    svc = service()
    assert svc.mem_limit == DEFAULT_MEMORY
    assert svc.cpus == DEFAULT_CPUS
    assert svc.pids_limit == 64
    assert svc.read_only is True


def test_builtin_profiles_load():
    from mauberesec.docker.labs import builtin_profiles

    profiles = builtin_profiles()
    assert "demo-web" in profiles
