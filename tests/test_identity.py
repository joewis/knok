import os
import stat

import pytest

from knok.identity import IdentityError, fingerprint, generate, load, validate_agent_id


def test_generate_produces_distinct_keys():
    a, b = generate("carl", "bridge.example"), generate("carl", "bridge.example")
    assert a.fingerprint != b.fingerprint
    assert a.agent_id == "carl@bridge.example"


@pytest.mark.parametrize("bad", ["Carl", "-carl", "car l", "a" * 40, "carl@x@y", "carl"])
def test_invalid_agent_ids_rejected(bad):
    with pytest.raises(IdentityError):
        validate_agent_id(bad)


@pytest.mark.parametrize("reserved", ["admin", "root", "system", "hub", "bridge"])
def test_reserved_names_rejected(reserved):
    with pytest.raises(IdentityError):
        generate(reserved, "bridge.example")


def test_save_is_0600_and_refuses_overwrite(tmp_path, identity):
    path = identity.save(tmp_path / "carl.key")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with pytest.raises(IdentityError):
        identity.save(path)


def test_save_load_round_trip(tmp_path, identity):
    path = identity.save(tmp_path / "carl.key")
    again = load(identity.agent_id, path, identity.fingerprint)
    assert again.fingerprint == identity.fingerprint


def test_load_refuses_a_key_that_is_not_the_registered_one(tmp_path, identity, peer):
    path = identity.save(tmp_path / "carl.key")
    with pytest.raises(IdentityError, match="not the registered"):
        load(identity.agent_id, path, peer.fingerprint)


def test_save_leaves_no_temporary_file_behind(tmp_path, identity):
    """#110: the key is written beside the target and linked into place, so the
    staging file must not survive a successful save."""
    path = identity.save(tmp_path / "carl.key")
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]


def test_load_refuses_a_group_readable_key(tmp_path, identity):
    """#109: the mode is checked at load, not only at creation — a key copied or
    restored from a backup is compromised whoever wrote it."""
    path = identity.save(tmp_path / "carl.key")
    os.chmod(path, 0o644)
    with pytest.raises(IdentityError, match="0600"):
        load(identity.agent_id, path, identity.fingerprint)

    os.chmod(path, 0o600)
    assert load(identity.agent_id, path, identity.fingerprint).fingerprint == identity.fingerprint


def test_fingerprint_is_stable(identity):
    assert identity.fingerprint.startswith("SHA256:")
    assert identity.fingerprint == fingerprint(identity.public_key)
