import functools
import hashlib
import logging

from golem_messages import cryptography
from golem_messages import datastructures
from golem_messages import exceptions
from golem_messages import serializer
from golem_messages import validators
from golem_messages.datastructures import masking
from golem_messages.datastructures import p2p as dt_p2p


logger = logging.getLogger(__name__)


def _fail_if(field_name, value, check, fail_msg):
    if not check(value):
        raise exceptions.FieldError(
            fail_msg,
            field=field_name,
            value=value,
        )


class TaskHeader(datastructures.Container):
    """
    Task header describes general information about task as an request and
    is propagated in the network as an offer for computing nodes
    """

    __slots__ = {
        'mask': (
            functools.partial(
                _fail_if,
                check=lambda x: isinstance(x, bytes),
                fail_msg="Should be bytes",
            ),
        ),
        'timestamp': (
            validators.validate_integer,
        ),
        'signature': (
            functools.partial(
                _fail_if,
                check=lambda x: isinstance(x, bytes),
                fail_msg="Should be bytes",
            ),
        ),
        'task_id': (validators.validate_varchar128, ),
        'task_owner': (
            functools.partial(
                _fail_if,
                check=lambda x: isinstance(x, (dict, dt_p2p.Node)),
                fail_msg="Should be a dict or Node",
            ),
        ),
        'deadline': (validators.validate_integer, ),
        'subtask_timeout': (
            validators.validate_integer,
            functools.partial(
                _fail_if,
                check=lambda x: x >= 0,
                fail_msg="Subtask timeout is less than 0",
            ),
        ),
        # environment.get_id()
        'environment': (validators.validate_varchar128, ),
        'min_version': (validators.validate_version, ),
        'estimated_memory': (validators.validate_integer, ),
        # maximum price that this (requestor) node
        # may pay for an hour of computation
        'max_price': (validators.validate_integer, ),
        'subtasks_count': (
            validators.validate_integer,
            functools.partial(
                _fail_if,
                check=lambda x: x > 0,
                fail_msg="Subtasks count is less than 1",
            ),
        ),
        'concent_enabled': (validators.validate_boolean, ),
    }

    REQUIRED = frozenset((
        'task_id',
        'task_owner',
        'subtasks_count',
        'min_version',
        'timestamp',
    ))

    def __repr__(self):
        return '<TaskHeader: %r>' % (self.task_id,)

    @classmethod
    def deserialize_task_owner(cls, value):
        if isinstance(value, dt_p2p.Node):
            return value
        return dt_p2p.Node(**value)

    @classmethod
    def deserialize_mask(cls, value):
        return masking.Mask(byte_repr=value)

    def sign(self, private_key: bytes) -> None:
        self.signature = cryptography.ecdsa_sign(  # noqa pylint: disable=attribute-defined-outside-init
            privkey=private_key,
            msghash=self.get_hash(),
        )

    def verify(self, public_key: bytes) -> bool:
        """
        :return: `True` if the signature is correct.
        :raises: `exceptions.InvalidSignature` if the signature is corrupted
        """
        if self.signature is None:
            raise exceptions.InvalidSignature("No signature")
        return cryptography.ecdsa_verify(
            pubkey=public_key,
            signature=self.signature,
            message=self.get_hash(),
        )

    def get_hash(self) -> bytes:
        sha = hashlib.sha1()
        d = self.to_dict()
        del d['signature']
        sha.update(serializer.dumps(d))
        return sha.digest()

    @classmethod
    def serialize_task_owner(cls, value):
        return value.to_dict()

    @classmethod
    def serialize_mask(cls, value):
        return value.to_bytes()
