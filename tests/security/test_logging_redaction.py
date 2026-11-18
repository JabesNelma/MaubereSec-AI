"""Security tests: structured logging never emits secrets."""

import json

from mauberesec.logging_setup import configure_logging, get_logger


def capture_structlog(capfd):
    configure_logging(json_output=True)
    return get_logger("test")


def test_json_log_redacts_key(capsys):
    log = capture_structlog(capsys)
    log.info("request", api_key="sk-proj-AbCdEfGh1234567890IjKlMnOp")
    out = capsys.readouterr().err
    line = json.loads(out.strip().splitlines()[-1])
    assert "sk-proj-" not in line["api_key"]
    assert line["api_key"] == "[REDACTED]"


def test_json_log_redacts_secret_in_message(capsys):
    log = capture_structlog(capsys)
    log.info("using token=supersecretvalue123 done")
    out = capsys.readouterr().err
    assert "supersecretvalue123" not in out
    assert "[REDACTED" in out
