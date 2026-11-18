"""Unit tests for the allowlisted Docker CLI wrapper."""

import pytest

from mauberesec.docker.client import DockerClient, DockerCommandError, _validate_args


def test_allowed_subcommands_pass_validation():
    _validate_args(["network", "create", "--subnet", "10.66.7.0/24", "net1"])
    _validate_args(["network", "inspect", "net1"])
    _validate_args(["container", "ls", "-a"])
    _validate_args(["run", "-d", "--name", "c1", "nginx:1.27-alpine"])
    _validate_args(["version", "--format", "{{.Server.Version}}"])


def test_non_allowlisted_subcommand_rejected():
    with pytest.raises(DockerCommandError, match="not in the allowlist"):
        _validate_args(["exec", "c1", "sh", "-c", "id"])


def test_privileged_rejected():
    with pytest.raises(DockerCommandError, match="forbidden"):
        _validate_args(["run", "--privileged", "nginx"])


def test_docker_socket_mount_rejected():
    with pytest.raises(DockerCommandError, match="forbidden"):
        _validate_args(["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "nginx"])


def test_host_path_mount_rejected():
    with pytest.raises(DockerCommandError, match="Host path mount"):
        _validate_args(["run", "-v", "/etc:/etc", "nginx"])
    with pytest.raises(DockerCommandError, match="Host path mount"):
        _validate_args(["run", "-v", "./src:/src", "nginx"])


def test_named_volume_mount_allowed():
    _validate_args(["run", "-v", "lab-output:/out", "nginx"])


def test_host_network_rejected():
    with pytest.raises(DockerCommandError, match="forbidden"):
        _validate_args(["run", "--network", "host", "nginx"])
    with pytest.raises(DockerCommandError, match="forbidden"):
        _validate_args(["run", "--network=host", "nginx"])


def test_empty_command_rejected():
    with pytest.raises(DockerCommandError):
        _validate_args([])


def test_client_unavailable_raises():
    client = DockerClient(docker_path="")
    assert client.available is False
    with pytest.raises(DockerCommandError, match="not found"):
        client.run(["version"])
