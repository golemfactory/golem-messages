import typing
import uuid

import eth_account.account
import eth_account.messages

from golem_messages.utils import uuid_to_bytes32

PromissoryNoteSig = typing.NamedTuple(
    'PromissoryNoteSig',
    [
        ('v', int),
        ('r', bytes),
        ('s', bytes),
    ]
)


class PromissoryNote:
    """
    When signed, represents a commitment, by a party, to allow the Concent
    service to make use of party's deposit (stored within the GNT Deposit smart
    contract) should the Concent service deem it necessary according to one of
    its use cases.

    A payment from the deposit can only be effected if such a commitment had
    been generated and signed and then provided to the GNT Deposit smart
    contract in the reimbursment transaction.

    Attributes
        address_from: str   the address of the deposit's owner
        address_to: str     the address to which the promissory note is issued
        amount: int         the (maximum) amount (in wei) that can be paid
                            out to the promissory note's recipient
        subtask_id: str     the id of the specific work for which the
                            promissory note has been issued

    """
    def __init__(
            self,
            address_from: str,
            address_to: str,
            amount: int,
            subtask_id: str,
    ):
        self.address_from = address_from
        self.address_to = address_to
        self.amount = amount
        self.subtask_id = subtask_id

    def __repr__(self):
        return "<{cls}: from: {address_from}, to: {address_to}, " \
               "amount: {amount}, subtask_id: {subtask_id}>"\
            .format(
                cls=self.__class__.__name__,
                address_from=self.address_from,
                address_to=self.address_to,
                amount=self.amount,
                subtask_id=self.subtask_id,
            )

    @property
    def hexmsg(self) -> str:
        return "0x" + \
               self.address_from[2:] + \
               self.address_to[2:] + \
               self.amount.to_bytes(32, byteorder='big').hex() + \
               uuid_to_bytes32(uuid.UUID(self.subtask_id)).hex()

    @property
    def hash(self):
        return eth_account.messages.defunct_hash_message(hexstr=self.hexmsg)

    def sign(self, privkey: bytes) -> PromissoryNoteSig:
        signed_message = eth_account.account.Account.signHash(
            message_hash=self.hash,
            private_key=privkey
        )
        v = signed_message['v']
        r = (signed_message['r']).to_bytes(32, byteorder='big')
        s = (signed_message['s']).to_bytes(32, byteorder='big')
        return PromissoryNoteSig(v, r, s)

    def sig_valid(self, promissory_note_sig: typing.Optional[tuple]) -> bool:
        if not promissory_note_sig:
            return False

        try:
            promissory_note_sig = PromissoryNoteSig(*promissory_note_sig)
        except TypeError as e:
            raise TypeError(
                "The provided promissory note sig: `{}` has wrong type. "
                "Must be a tuple with format: {}".format(
                    promissory_note_sig,
                    PromissoryNoteSig._field_types,
                )
            ) from e

        address_from = eth_account.Account.recoverHash(
            message_hash=self.hash,
            vrs=promissory_note_sig
        )
        return self.address_from == address_from
