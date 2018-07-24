import unittest

from golem_messages import cryptography
from golem_messages import message
from golem_messages import serializer
from golem_messages import shortcuts

from golem_messages import factories


class MessageTestCase(unittest.TestCase):
    def equal_after_processing(self, o):
        s = serializer.dumps(o)
        o2 = serializer.loads(s)
        self.assertEqual(o, o2)

    def test_message(self):
        m = message.Ping()
        self.equal_after_processing(m)

    def test_message_list(self):
        aList = [message.Ping()]
        self.equal_after_processing(aList)

    def test_message_dict(self):
        d = {'m': message.Ping()}
        self.equal_after_processing(d)

    def test_message_sig(self):
        """Signed message inside a signed message"""

        concent_keys = cryptography.ECCx(None)
        provider_keys = cryptography.ECCx(None)
        requestor_keys = cryptography.ECCx(None)

        report_computed_task = factories.tasks.ReportComputedTaskFactory()

        # Dump TaskToCompute to make it signed
        s_rct = shortcuts.dump(
            report_computed_task,
            requestor_keys.raw_privkey,
            provider_keys.raw_pubkey,
        )

        # Load TaskToCompute back to its original format
        # Task TaskToCompute is verified correctly
        report_computed_task = shortcuts.load(
            s_rct,
            provider_keys.raw_privkey,
            requestor_keys.raw_pubkey,
        )

        first_sig = report_computed_task.sig
        first_hash = report_computed_task.get_short_hash()

        force_report = message.concents.ForceReportComputedTask()
        force_report.report_computed_task = report_computed_task

        s_force_report = shortcuts.dump(
            force_report,
            provider_keys.raw_privkey,
            concent_keys.raw_pubkey,
        )

        force_report = shortcuts.load(
            s_force_report,
            concent_keys.raw_privkey,
            provider_keys.raw_pubkey,
        )

        second_sig = force_report.report_computed_task.sig
        second_hash = force_report.report_computed_task.get_short_hash()

        self.assertEqual(first_sig, second_sig)
        self.assertEqual(first_hash, second_hash)

        # Now, attached TaskToCompute should still be verified using
        # original key. ecdsa_verify will raise InvalidSignature on
        # failure.
        cryptography.ecdsa_verify(
            requestor_keys.raw_pubkey,
            force_report.report_computed_task.sig,
            force_report.report_computed_task.get_short_hash(),
        )
