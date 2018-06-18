from uuid import UUID

from golem_messages import utils


def test_bytes_uuid():
    uuid = UUID(bytes=b'0123456789012345')
    b = utils.uuid_to_bytes32(uuid)
    assert len(b) == 32
    assert utils.bytes32_to_uuid(b) == uuid
