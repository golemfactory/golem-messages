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
        msg.header.type_,
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


def call_subfactory(object_factory: factory.Factory,
                    create, extracted, **kwargs):
    if not (create or extracted or kwargs):
        return None

    generate = kwargs.pop('_generate', None)
    if kwargs or generate:
        extracted = object_factory(**kwargs)

    return extracted


def optional_subfactory(field: str, object_factory: factory.Factory):
    """
    Defines an optionally-called sub-factory triggered using a `___generate`
    suffix on the parent factory's appropriate keyword argument

    :param field: the name of the field the subfactory assigns to
    :param object_factory: the factory to be called
    :return: the sub-factory
    """
    def _subfactory(obj, create, extracted, **kwargs):
        setattr(
            obj, field,
            call_subfactory(object_factory, create, extracted, **kwargs)
        )
    return factory.post_generation(_subfactory)


class MessageFactory(factory.Factory):

    @staticmethod
    def sign_message(msg: 'Message', _, __, **kwargs):
        privkey = kwargs.pop('privkey', None)

        if kwargs:
            raise factory.errors.InvalidDeclarationError(
                "Unknown arguments encountered %s" % list(kwargs.keys()))

        if privkey:
            msg.sign_message(privkey)

    # pylint: disable=no-self-argument

    @factory.post_generation
    def sign(msg: 'Message', _, __, **kwargs):
        MessageFactory.sign_message(msg, _, __, **kwargs)

    # pylint: enable=no-self-argument
