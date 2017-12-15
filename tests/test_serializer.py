from golem_messages import cryptography
from golem_messages import message
from golem_messages import serializer
from golem_messages import shortcuts
import unittest


class EqualityMixIn:
    def equal_after_processing(self, o):
        s = serializer.dumps(o)
        o2 = serializer.loads(s)
        self.assertEqual(o, o2)


class EnumTestCase(unittest.TestCase):
    def test_disconnect_reason(self):
        r = message.Disconnect.REASON.TooManyPeers
        s = serializer.dumps(r)
        r2 = serializer.loads(s)
        self.assertIs(r, r2)


class MessageTestCase(unittest.TestCase, EqualityMixIn):
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
        concent_keys = cryptography.ECCx(None)
        provider_keys = cryptography.ECCx(None)
        requestor_keys = cryptography.ECCx(None)

        task_to_compute = message.TaskToCompute()
        ctd = message.ComputeTaskDef({'task_id': 20, })
        task_to_compute.compute_task_def = ctd

        # Dump TaskToCompute to make it signed
        s_task_to_compute = shortcuts.dump(
            task_to_compute,
            requestor_keys.raw_privkey,
            provider_keys.raw_pubkey,
        )

        # Load TaskToCompute back to its original format
        task_to_compute = shortcuts.load(
            s_task_to_compute,
            provider_keys.raw_privkey,
            requestor_keys.raw_pubkey,
        )

        first_sig = task_to_compute.sig
        first_hash = task_to_compute.get_short_hash()

        # Task TaskToCompute is verified correctly
        cryptography.ecdsa_verify(
            requestor_keys.raw_pubkey,
            task_to_compute.sig,
            task_to_compute.get_short_hash(),
        )

        force_report = message.ForceReportComputedTask()
        force_report.task_to_compute = task_to_compute

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

        second_sig = force_report.task_to_compute.sig
        second_hash = force_report.task_to_compute.get_short_hash()

        self.assertEqual(first_sig, second_sig)
        self.assertEqual(first_hash, second_hash)

        # Now, attached TaskToCompute should still be verified using
        # original key
        cryptography.ecdsa_verify(
            requestor_keys.raw_pubkey,
            force_report.task_to_compute.sig,
            force_report.task_to_compute.get_short_hash(),
        )
