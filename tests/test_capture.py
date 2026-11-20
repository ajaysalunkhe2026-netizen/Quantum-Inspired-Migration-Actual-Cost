"""Unit tests for conservative OpenSSL diagnostic parsing."""

from pqtls.capture import NEGOTIATED, _normalise_group


def test_negotiated_group_regex_extracts_tls13_group() -> None:
    transcript = "Negotiated TLS1.3 group: X25519MLKEM768"
    match = NEGOTIATED[0].search(transcript)

    assert match is not None
    assert _normalise_group(match.group(1)) == "X25519MLKEM768"


def test_server_temp_key_annotation_is_removed() -> None:
    transcript = "Server Temp Key: X25519, 253 bits"
    match = NEGOTIATED[1].search(transcript)

    assert match is not None
    assert _normalise_group(match.group(1)) == "X25519"


def test_group_matching_does_not_accept_classical_prefix_of_hybrid() -> None:
    requested_group = "X25519"
    negotiated_group = _normalise_group("X25519MLKEM768")

    assert requested_group.casefold() != negotiated_group.casefold()
