# For backwards compatibility import all old messages by name
# pylint: disable=unused-import
# pylint: disable=cyclic-import
from golem_messages.message.base import Message  # noqa
from golem_messages.message.base import Hello  # noqa
from golem_messages.message.base import RandVal  # noqa
from golem_messages.message.base import Disconnect  # noqa
from golem_messages.message.base import ChallengeSolution  # noqa
from golem_messages.message.p2p import Ping  # noqa
from golem_messages.message.p2p import Pong  # noqa
from golem_messages.message.p2p import GetPeers  # noqa
from golem_messages.message.p2p import GetTasks  # noqa
from golem_messages.message.p2p import Peers  # noqa
from golem_messages.message.p2p import Tasks  # noqa
from golem_messages.message.p2p import RemoveTask  # noqa
from golem_messages.message.p2p import FindNode  # noqa
from golem_messages.message.p2p import GetResourcePeers  # noqa
from golem_messages.message.p2p import ResourcePeers  # noqa
from golem_messages.message.p2p import WantToStartTaskSession  # noqa
from golem_messages.message.p2p import SetTaskSession  # noqa
from golem_messages.message.p2p import Degree  # noqa
from golem_messages.message.p2p import Gossip  # noqa
from golem_messages.message.p2p import StopGossip  # noqa
from golem_messages.message.p2p import LocRank  # noqa
from golem_messages.message.tasks import ComputeTaskDef  # noqa
from golem_messages.message.tasks import CannotAssignTask  # noqa
from golem_messages.message.tasks import CannotComputeTask  # noqa
from golem_messages.message.tasks import TaskToCompute  # noqa
from golem_messages.message.tasks import WantToComputeTask  # noqa
from golem_messages.message.tasks import ReportComputedTask  # noqa
from golem_messages.message.tasks import TaskResultHash  # noqa
from golem_messages.message.tasks import TaskFailure  # noqa
from golem_messages.message.tasks import GetTaskResult  # noqa
from golem_messages.message.tasks import StartSessionResponse  # noqa
from golem_messages.message.tasks import WaitingForResults  # noqa
from golem_messages.message.tasks import DeltaParts  # noqa
from golem_messages.message.tasks import SubtaskPayment  # noqa
from golem_messages.message.tasks import SubtaskPaymentRequest  # noqa
from golem_messages.message.tasks import GetResource  # noqa
from golem_messages.message.resources import PushResource  # noqa
from golem_messages.message.resources import HasResource  # noqa
from golem_messages.message.resources import WantsResource  # noqa
from golem_messages.message.resources import PullResource  # noqa
from golem_messages.message.resources import PullAnswer  # noqa
from golem_messages.message.resources import ResourceList  # noqa
from golem_messages.message.resources import ResourceHandshakeStart  # noqa
from golem_messages.message.resources import ResourceHandshakeNonce  # noqa
from golem_messages.message.resources import ResourceHandshakeVerdict  # noqa
from golem_messages.message.concents import ServiceRefused  # noqa
from golem_messages.message.concents import ForceReportComputedTask  # noqa
from golem_messages.message.concents import AckReportComputedTask  # noqa
from golem_messages.message.concents import RejectReportComputedTask  # noqa
from golem_messages.message.concents import VerdictReportComputedTask  # noqa
from golem_messages.message.concents import FileTransferToken  # noqa
# pylint: enable=unused-import

from . import base
from . import concents
from . import p2p
from . import resources
from . import tasks
# pylint: enable=cyclic-import


# Message types that are allowed to be sent in the network
registered_message_types = {}


def init_messages():
    """Add supported messages to register messages list"""
    if registered_message_types:
        return
    for message_class in (
            # Basic messages
            base.Hello,
            base.RandVal,
            base.Disconnect,
            base.ChallengeSolution,

            # P2P messages
            p2p.Ping,
            p2p.Pong,
            p2p.GetPeers,
            p2p.GetTasks,
            p2p.Peers,
            p2p.Tasks,
            p2p.RemoveTask,
            p2p.FindNode,
            p2p.GetResourcePeers,
            p2p.ResourcePeers,
            p2p.WantToStartTaskSession,
            p2p.SetTaskSession,
            # Ranking messages
            p2p.Degree,
            p2p.Gossip,
            p2p.StopGossip,
            p2p.LocRank,

            # Task messages
            tasks.CannotAssignTask,
            tasks.CannotComputeTask,
            tasks.TaskToCompute,
            tasks.WantToComputeTask,
            tasks.ReportComputedTask,
            tasks.TaskResultHash,
            tasks.TaskFailure,
            tasks.GetTaskResult,
            tasks.StartSessionResponse,

            tasks.WaitingForResults,
            tasks.SubtaskResultsAccepted,
            tasks.SubtaskResultsRejected,
            tasks.DeltaParts,
            tasks.GetResource,

            # Resource messages
            resources.PushResource,
            resources.HasResource,
            resources.WantsResource,
            resources.PullResource,
            resources.PullAnswer,
            resources.ResourceList,

            resources.ResourceHandshakeStart,
            resources.ResourceHandshakeNonce,
            resources.ResourceHandshakeVerdict,

            tasks.SubtaskPayment,
            tasks.SubtaskPaymentRequest,

            # Concent messages
            concents.ServiceRefused,
            concents.ForceReportComputedTask,
            concents.AckReportComputedTask,
            concents.RejectReportComputedTask,
            concents.VerdictReportComputedTask,
            concents.FileTransferToken,
            concents.SubtaskResultsVerify,
            concents.AckSubtaskResultsVerify,
            concents.SubtaskResultsSettled,
            concents.ForceGetTaskResult,
            concents.ForceGetTaskResultAck,
            concents.ForceGetTaskResultFailed,
            concents.ForceGetTaskResultRejected,
            concents.ForceGetTaskResultUpload,
            concents.ForceSubtaskResultsRejected,
    ):
        if message_class.TYPE in registered_message_types:
            raise RuntimeError(
                "Duplicated message {}.TYPE: {}"
                .format(message_class.__name__, message_class.TYPE)
            )
        registered_message_types[message_class.TYPE] = message_class


init_messages()
