# pylint:disable=no-self-use
import unittest

from golem_messages import cryptography
from golem_messages import exceptions
from golem_messages import factories

from golem_messages.datastructures.tasks import TaskHeader
from golem_messages.factories.datastructures.tasks import TaskHeaderFactory
from golem_messages.utils import encode_hex


class TaskMessageVerificationTest(unittest.TestCase):
    @staticmethod
    def _fake_keys():
        return cryptography.ECCx(None)

    def setUp(self):
        self.provider_keys = self._fake_keys()
        self.requestor_keys = self._fake_keys()
        self.other_keys = self._fake_keys()

    def get_ttc(self, **kwargs):
        task_header: TaskHeader = TaskHeaderFactory()
        task_header.sign(self.requestor_keys.raw_privkey)  # noqa pylint: disable=no-value-for-parameter
        return factories.tasks.TaskToComputeFactory(
            requestor_public_key=encode_hex(self.requestor_keys.raw_pubkey),
            want_to_compute_task=factories.tasks.WantToComputeTaskFactory(
                provider_public_key=encode_hex(self.provider_keys.raw_pubkey),
                task_header=task_header,
            ),
            **kwargs,
        )

    def get_rtc(self, **kwargs):
        return factories.tasks.ReportComputedTaskFactory(
            **kwargs,
        )

    def get_signed_rtc(self):
        return self.get_rtc(
            task_to_compute=self.get_ttc(
                sign__privkey=self.requestor_keys.raw_privkey
            ),
            sign__privkey=self.provider_keys.raw_privkey
        )

    def test_validate_ownership(self):
        ttc = self.get_ttc(
            sign__privkey=self.requestor_keys.raw_privkey,
        )
        self.assertTrue(ttc.validate_ownership())

    def test_validate_ownership_no_sig(self):
        ttc = self.get_ttc()
        with self.assertRaises(exceptions.InvalidSignature):
            ttc.validate_ownership()

    def test_validate_ownership_mismatch(self):
        ttc = self.get_ttc(
            sign__privkey=self.provider_keys.raw_privkey,
        )
        with self.assertRaises(exceptions.InvalidSignature):
            ttc.validate_ownership()

    def test_chain(self):
        rtc = self.get_signed_rtc()
        self.assertTrue(rtc.validate_ownership_chain())

    def test_chain_parent_no_sig(self):
        rtc = self.get_rtc(
            task_to_compute=self.get_ttc(
                sign__privkey=self.requestor_keys.raw_privkey
            ),
        )
        with self.assertRaises(exceptions.InvalidSignature):
            rtc.validate_ownership_chain()

    def test_chain_child_no_sig(self):
        rtc = self.get_rtc(
            task_to_compute=self.get_ttc(),
            sign__privkey=self.provider_keys.raw_privkey
        )
        with self.assertRaises(exceptions.InvalidSignature):
            rtc.validate_ownership_chain()

    def test_chain_parent_mismatch(self):
        rtc = self.get_rtc(
            task_to_compute=self.get_ttc(
                sign__privkey=self.requestor_keys.raw_privkey
            ),
            sign__privkey=self.requestor_keys.raw_privkey
        )
        with self.assertRaises(exceptions.InvalidSignature):
            rtc.validate_ownership_chain()

    def test_chain_child_mismatch(self):
        rtc = self.get_rtc(
            task_to_compute=self.get_ttc(
                sign__privkey=self.provider_keys.raw_privkey
            ),
            sign__privkey=self.provider_keys.raw_privkey
        )
        with self.assertRaises(exceptions.InvalidSignature):
            rtc.validate_ownership_chain()

    def test_verify_owners(self):
        rtc = self.get_signed_rtc()
        self.assertTrue(
            rtc.verify_owners(
                provider_public_key=self.provider_keys.raw_pubkey,
                requestor_public_key=self.requestor_keys.raw_pubkey,
            )
        )

    def test_verify_owners_provider_only(self):
        rtc = self.get_signed_rtc()
        self.assertTrue(
            rtc.verify_owners(
                provider_public_key=self.provider_keys.raw_pubkey))

    def test_verify_owners_requestor_only(self):
        rtc = self.get_signed_rtc()
        self.assertTrue(
            rtc.verify_owners(
                requestor_public_key=self.requestor_keys.raw_pubkey))

    def test_verify_owners_provider_mismatch(self):
        rtc = self.get_signed_rtc()
        with self.assertRaisesRegex(exceptions.OwnershipMismatch, 'provider'):
            rtc.verify_owners(
                provider_public_key=self.other_keys.raw_pubkey,
                requestor_public_key=self.requestor_keys.raw_pubkey,
            )

    def test_verify_owners_requestor_mismatch(self):
        rtc = self.get_signed_rtc()
        with self.assertRaisesRegex(exceptions.OwnershipMismatch, 'requestor'):
            rtc.verify_owners(
                provider_public_key=self.provider_keys.raw_pubkey,
                requestor_public_key=self.other_keys.raw_pubkey,
            )
