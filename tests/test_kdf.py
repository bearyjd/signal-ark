"""Test KDF against libsignal reference test vectors."""

from signal_ark.kdf import (
    aep_to_backup_key,
    aci_to_service_id_binary,
    backup_key_to_backup_id,
    backup_key_to_message_backup_key,
    validate_aep,
)

TEST_AEP = "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l"
TEST_ACI = "659aa5f4-a28d-fcc1-1ea1-b997537a3d95"
TEST_BACKUP_KEY = bytes.fromhex("ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985")
TEST_BACKUP_ID = bytes.fromhex("8a624fbc45379043f39f1391cddc5fe8")

TEST_FS_TOKEN = bytes.fromhex("69207061737320746865206b6e69666520746f207468652061786f6c6f746c21")

LEGACY_HMAC_KEY = bytes.fromhex("f425e22a607c529717e1e1b29f9fe139f9d1c7e7d01e371c7753c544a3026649")
LEGACY_AES_KEY = bytes.fromhex("e143f4ad5668d8bfed2f88562f0693f53bda2c0e55c9d71730f30e24695fd6df")

MODERN_HMAC_KEY = bytes.fromhex("20e6ab57b87e051f3e695e953cf8a261dd307e4f92ae2921673f1d397e07887b")
MODERN_AES_KEY = bytes.fromhex("602af6ecfc09d695a8d58da9f18225e967979c5e03543ca0224a03cca3d9735e")


def test_validate_aep() -> None:
    assert validate_aep(TEST_AEP) == TEST_AEP
    assert validate_aep(TEST_AEP.upper()) == TEST_AEP


def test_aep_to_backup_key() -> None:
    assert aep_to_backup_key(TEST_AEP) == TEST_BACKUP_KEY


def test_aci_to_service_id_binary() -> None:
    result = aci_to_service_id_binary(TEST_ACI)
    assert len(result) == 16
    assert result == bytes.fromhex("659aa5f4a28dfcc11ea1b997537a3d95")


def test_backup_key_to_backup_id() -> None:
    assert backup_key_to_backup_id(TEST_BACKUP_KEY, TEST_ACI) == TEST_BACKUP_ID


def test_legacy_message_backup_key() -> None:
    hmac_key, aes_key = backup_key_to_message_backup_key(TEST_BACKUP_KEY, TEST_BACKUP_ID)
    assert hmac_key == LEGACY_HMAC_KEY
    assert aes_key == LEGACY_AES_KEY


def test_modern_message_backup_key() -> None:
    hmac_key, aes_key = backup_key_to_message_backup_key(
        TEST_BACKUP_KEY, TEST_BACKUP_ID, forward_secrecy_token=TEST_FS_TOKEN
    )
    assert hmac_key == MODERN_HMAC_KEY
    assert aes_key == MODERN_AES_KEY
