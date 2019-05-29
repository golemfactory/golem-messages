import unittest

from golem_messages import cryptography
from golem_messages import factories
from golem_messages import message

from golem_messages.utils import encode_hex

from tests.message import mixins


class AckReportComputedTaskTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = message.tasks.AckReportComputedTask
    FACTORY = factories.tasks.AckReportComputedTaskFactory
    TASK_ID_PROVIDER = 'report_computed_task'

    def test_validate_owner_requestor(self):
        requestor_keys = cryptography.ECCx(None)
        arct = self.FACTORY(
            report_computed_task__task_to_compute__requestor_public_key=encode_hex(requestor_keys.raw_pubkey),  # noqa pylint:disable=line-too-long
            sign__privkey=requestor_keys.raw_privkey,
        )
        self.assertTrue(arct.validate_ownership())

    def test_validate_owner_concent(self):
        concent_keys = cryptography.ECCx(None)
        arct = self.FACTORY(
            sign__privkey=concent_keys.raw_privkey,
        )
        self.assertTrue(
            arct.validate_ownership(
                concent_public_key=concent_keys.raw_pubkey))
