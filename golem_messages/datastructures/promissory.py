import typing

import eth_account.account
import eth_account.messages


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

    @property
    def hexmsg(self) -> str:
        return "0x" + \
               self.address_from[2:] + \
               self.address_from[2:] + \
               self.amount.to_bytes(32, byteorder='big').hex() + \
               self.subtask_id.encode('ascii').hex()

    @property
    def hash(self):
        return eth_account.messages.defunct_hash_message(hexstr=self.hexmsg)

    def sign(self, privkey: bytes) -> PromissoryNoteSig:
        account = eth_account.account.Account.privateKeyToAccount(
            privkey=privkey)
        signed_message = account.signHash(self.hash)
        v = signed_message['v']
        r = (signed_message['r']).to_bytes(32, byteorder='big')
        s = (signed_message['s']).to_bytes(32, byteorder='big')
        return PromissoryNoteSig(v, r, s)

    def sig_valid(self, promissory_note_sig: PromissoryNoteSig) -> bool:
        address_from = eth_account.Account.recoverHash(
            self.hash, promissory_note_sig
        )
        return self.address_from == address_from
