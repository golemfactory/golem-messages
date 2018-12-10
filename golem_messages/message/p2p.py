from golem_messages import exceptions
from golem_messages.datastructures import tasks as dt_tasks
from golem_messages.register import library

from . import base

################
# P2P Messages #
################

P2P_MESSAGE_BASE = 1000


@library.register(P2P_MESSAGE_BASE + 1)
class Ping(base.Message):
    SIGN = False

    __slots__ = base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 2)
class Pong(base.Message):
    SIGN = False

    __slots__ = base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 3)
class GetPeers(base.Message):
    SIGN = False

    __slots__ = base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 4)
class Peers(base.Message):
    SIGN = False

    __slots__ = ['peers'] + base.Message.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.peers = self.peers or []


@library.register(P2P_MESSAGE_BASE + 5)
class GetTasks(base.Message):
    SIGN = False

    __slots__ = base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 6)
class Tasks(base.Message):
    __slots__ = ['tasks'] + base.Message.__slots__

    def __init__(self, **kwargs):
        """
        Create message containing information about tasks
        :param list tasks: list of tasks information (subset of
                           taskserver.get_tasks_headers())
        """
        super().__init__(**kwargs)
        self.tasks = self.tasks or []

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key=key, value=value)
        if key == 'tasks':
            value = self.deserialize_tasks(value)
        return value

    @classmethod
    def deserialize_tasks(cls, value):
        if not isinstance(value, list):
            raise exceptions.FieldError(
                "Should be a list not {}".format(type(value)),
                field="tasks",
                value=value,
            )
        parsed = []
        for header_dict in value:
            if not isinstance(header_dict, dict):
                raise exceptions.FieldError(
                    "dict is expected not {}".format(
                        type(header_dict),
                    ),
                    field="tasks",
                    value=header_dict,
                )
            parsed.append(dt_tasks.TaskHeader(**header_dict))
        return parsed

    def serialize_slot(self, key, value):
        value = super().serialize_slot(key=key, value=value)
        if key == "tasks":
            if not isinstance(value, list):
                raise exceptions.FieldError(
                    "Should be a list not {}".format(type(value)),
                    field="tasks",
                    value=value,
                )
            value = [task_header.to_dict() for task_header in value]
        return value


@library.register(P2P_MESSAGE_BASE + 7)
class RemoveTask(base.Message):
    """
    Message that is send by requestor that wants to cancel further
    broadcasting information about this task.
    """
    __slots__ = ['task_id'] + base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 8)
class GetResourcePeers(base.Message):
    """Request for resource peers"""
    SIGN = False

    __slots__ = base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 9)
class ResourcePeers(base.Message):
    SIGN = False

    __slots__ = ['resource_peers'] + base.Message.__slots__

    def __init__(self, **kwargs):
        """
        Create message containing information about resource peers
        :param list resource_peers: list of peers information
        """
        super().__init__(**kwargs)
        self.resource_peers = self.resource_peers or []


@library.register(P2P_MESSAGE_BASE + 10)
class Degree(base.Message):
    SIGN = False

    __slots__ = ['degree'] + base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 11)
class Gossip(base.Message):
    SIGN = False

    __slots__ = ['gossip'] + base.Message.__slots__

    def __init__(self, **kwargs):
        """
        Create gossip message
        :param list gossip: gossip to be send
        """
        super().__init__(**kwargs)
        self.gossip = self.gossip or []


@library.register(P2P_MESSAGE_BASE + 12)
class StopGossip(base.Message):
    """Create stop gossip message"""
    SIGN = False

    __slots__ = base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 13)
class LocRank(base.Message):
    SIGN = False

    __slots__ = ['node_id', 'loc_rank'] + base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 14)
class FindNode(base.Message):
    SIGN = False

    __slots__ = ['node_key_id'] + base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 15)
class WantToStartTaskSession(base.Message):
    __slots__ = [
        'node_info',
        'conn_id',
        'super_node_info'
    ] + base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 16)
class SetTaskSession(base.Message):
    __slots__ = [
        'key_id',
        'node_info',
        'conn_id',
        'super_node_info',
    ] + base.Message.__slots__


@library.register(P2P_MESSAGE_BASE + 17)
class RemoveTaskContainer(base.Message):
    """
    Message that contains RemoveTask messages signed by task owners. Other nodes
    uses this container to propagate information about tasks cancellation.
    """
    __slots__ = ['remove_tasks'] + base.Message.__slots__
    MSG_SLOTS = {
        'remove_tasks': base.MessageSlotDefinition(RemoveTask, is_list=True),
    }
