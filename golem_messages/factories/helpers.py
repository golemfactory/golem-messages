# pylint: disable=too-few-public-methods
import typing
import factory

from golem_messages import datastructures

if typing.TYPE_CHECKING:
    from golem_messages.message.base import Message  # noqa pylint:disable=unused-import


def override_timestamp(
        msg: 'Message',
        timestamp: int) -> None:
    new_hdr = datastructures.MessageHeader(
        msg.TYPE,
        timestamp,
        msg.encrypted,
    )
    msg.header = new_hdr


def clone_message(
        msg: 'Message',
        override_class: 'Message' = None,
        override_header=None) -> 'Message':
    msg_class = override_class or msg.__class__
    return msg_class(
        header=override_header or msg.header,
        sig=msg.sig,
        slots=msg.slots(),
    )


class MessageFactory(factory.Factory):

    # pylint: disable=no-self-argument

    @factory.post_generation
    def sign(msg: 'Message', _, __, **kwargs):
        privkey = kwargs.pop('privkey', None)

        if kwargs:
            raise factory.errors.InvalidDeclarationError(
                "Unknown arguments encountered %s" % list(kwargs.keys()))

        if privkey:
            msg.sign_message(privkey)

    # pylint: enable=no-self-argument
