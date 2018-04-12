import typing

if typing.TYPE_CHECKING:
    from golem_messages.message.base import Message  # noqa pylint:disable=unused-import


def clone_message(
        msg: 'Message', override_class: 'Message' = None) -> 'Message':
    msg_class = override_class or msg.__class__
    return msg_class(
        header=msg.header,
        sig=msg.sig,
        slots=msg.slots(),
    )
