from . import base

################
# P2P Messages #
################

P2P_MESSAGE_BASE = 1000


class Ping(base.Message):
    TYPE = P2P_MESSAGE_BASE + 1
    SIGN = False

    __slots__ = base.Message.__slots__


class Pong(base.Message):
    TYPE = P2P_MESSAGE_BASE + 2
    SIGN = False

    __slots__ = base.Message.__slots__


class GetPeers(base.Message):
    TYPE = P2P_MESSAGE_BASE + 3
    SIGN = False

    __slots__ = base.Message.__slots__


class Peers(base.Message):
    TYPE = P2P_MESSAGE_BASE + 4
    SIGN = False

    __slots__ = ['peers'] + base.Message.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.peers = self.peers or []


class GetTasks(base.Message):
    TYPE = P2P_MESSAGE_BASE + 5

    __slots__ = base.Message.__slots__


class Tasks(base.Message):
    TYPE = P2P_MESSAGE_BASE + 6

    __slots__ = ['tasks'] + base.Message.__slots__

    def __init__(self, **kwargs):
        """
        Create message containing information about tasks
        :param list tasks: list of tasks information (subset of
                           taskserver.get_tasks_headers())
        """
        super().__init__(**kwargs)
        self.tasks = self.tasks or []


class RemoveTask(base.Message):
    """
    Message that is send by requestor that wants to cancel further
    broadcasting information about this task.
    """
    TYPE = P2P_MESSAGE_BASE + 7

    __slots__ = ['task_id'] + base.Message.__slots__


class GetResourcePeers(base.Message):
    """Request for resource peers"""
    TYPE = P2P_MESSAGE_BASE + 8
    SIGN = False

    __slots__ = base.Message.__slots__


class ResourcePeers(base.Message):
    TYPE = P2P_MESSAGE_BASE + 9
    SIGN = False

    __slots__ = ['resource_peers'] + base.Message.__slots__

    def __init__(self, **kwargs):
        """
        Create message containing information about resource peers
        :param list resource_peers: list of peers information
        """
        super().__init__(**kwargs)
        self.resource_peers = self.resource_peers or []


class Degree(base.Message):
    TYPE = P2P_MESSAGE_BASE + 10
    SIGN = False

    __slots__ = ['degree'] + base.Message.__slots__


class Gossip(base.Message):
    TYPE = P2P_MESSAGE_BASE + 11
    SIGN = False

    __slots__ = ['gossip'] + base.Message.__slots__

    def __init__(self, **kwargs):
        """
        Create gossip message
        :param list gossip: gossip to be send
        """
        super().__init__(**kwargs)
        self.gossip = self.gossip or []


class StopGossip(base.Message):
    """Create stop gossip message"""
    TYPE = P2P_MESSAGE_BASE + 12
    SIGN = False

    __slots__ = base.Message.__slots__


class LocRank(base.Message):
    TYPE = P2P_MESSAGE_BASE + 13
    SIGN = False

    __slots__ = ['node_id', 'loc_rank'] + base.Message.__slots__


class FindNode(base.Message):
    TYPE = P2P_MESSAGE_BASE + 14
    SIGN = False

    __slots__ = ['node_key_id'] + base.Message.__slots__


class WantToStartTaskSession(base.Message):
    TYPE = P2P_MESSAGE_BASE + 15

    __slots__ = [
        'node_info',
        'conn_id',
        'super_node_info'
    ] + base.Message.__slots__


class SetTaskSession(base.Message):
    TYPE = P2P_MESSAGE_BASE + 16

    __slots__ = [
        'key_id',
        'node_info',
        'conn_id',
        'super_node_info',
    ] + base.Message.__slots__


class RemoveTaskContainer(base.Message):
    """
    Message that contains RemoveTask messages signed by task owners. Other nodes
    uses this container to propagate information about tasks cancellation.
    """

    TYPE = P2P_MESSAGE_BASE + 17

    __slots__ = ['remove_tasks'] + base.Message.__slots__

    @base.verify_slot_list('remove_tasks', RemoveTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)
