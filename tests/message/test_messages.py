import os
import random
import time
import unittest
import unittest.mock as mock
import uuid

from golem_messages import datastructures as dt
from golem_messages import factories
from golem_messages import message
from golem_messages import shortcuts
from golem_messages.factories.datastructures import p2p as dt_p2p_factory
from golem_messages.factories.datastructures import tasks as dt_tasks_factory

from tests.message import helpers


class InitializationTestCase(unittest.TestCase):
    def test_default_slots(self):
        """Slots initialization to None"""
        msg = message.Hello()
        for key in msg.__slots__:
            if key in message.Message.__slots__:
                continue
            if key.startswith('_'):
                continue
            self.assertIsNone(getattr(msg, key))

    def test_kwarg(self):
        challenge = 'Tuż nad Bugiem, z lewej strony,'
        msg = message.Hello(challenge=challenge)
        self.assertEqual(msg.challenge, challenge)

    def test_slot(self):
        challenge = 'Tuż nad Bugiem, z lewej strony,'
        msg = message.Hello(slots=[('challenge', challenge), ])
        self.assertEqual(msg.challenge, challenge)

    def test_kwarg_and_slot(self):
        challenge_kwarg = 'Tuż nad Bugiem, z lewej strony,'
        challenge_slot = 'Stoi wielki bór zielony.'
        msg = message.Hello(
            challenge=challenge_kwarg,
            slots=[('challenge', challenge_slot), ],
        )
        self.assertEqual(msg.challenge, challenge_slot)


class MessagesTestCase(unittest.TestCase):
    @mock.patch('golem_messages.message.base.verify_time')
    def test_timestamp_and_timezones(self, *_):
        epoch_t = 1475238345

        def set_tz(tz):
            os.environ['TZ'] = tz
            try:
                time.tzset()
            except AttributeError:
                raise unittest.SkipTest("tzset required")

        set_tz('Europe/Warsaw')
        warsaw_time = time.localtime(epoch_t)
        msg_pre = message.Hello(header=dt.MessageHeader(
            0,
            epoch_t,
            False,
        ))
        data = shortcuts.dump(msg_pre, None, None)
        set_tz('US/Eastern')
        msg_post = shortcuts.load(data, None, None)
        newyork_time = time.localtime(msg_post.timestamp)
        self.assertNotEqual(warsaw_time, newyork_time)
        self.assertEqual(time.gmtime(epoch_t), time.gmtime(msg_post.timestamp))

    def test_message_randval(self):
        rand_val = random.random()
        msg = message.RandVal(rand_val=rand_val)
        expected = [
            ['rand_val', rand_val],
        ]
        self.assertEqual(expected, msg.slots())

    def test_message_challenge_solution(self):
        solution = (
            'O gajach świętych, z których i drew zwalonych wichrem uprzątnąć'
            ' się nie godziło, opowiada Długosz (XIII, 160), że świętymi'
            ' były i zwierzęta chroniące się w nich, tak iż przez'
            ' ciągły ów zwyczaj czworonożne i ptactwo tych lasów, jakby domowe'
            ' jakie, nie stroniło od ludzi. Skoro zważymy, że dla Litwina gaje'
            ' takie były rzeczywiście nietykalnymi, że sam Mindowg nie ważył'
            ' się w nie wchodzić lub różdżkę w nich ułamać,'
            ' zrozumiemy to podanie. Toż samo donosi w starożytności'
            ' Strabon o Henetach: były u nich dwa gaje, Hery i Artemidy,'
            ' „w gajach tych ułaskawiły się zwierzęta i jelenie z wilkami'
            ' się kupiły; gdy się ludzie zbliżali i dotykali ich, nie uciekały;'
            ' skoro gonione od psów tu się schroniły, ustawała pogoń”. I bardzo'
            ' trzeźwi mitografowie uznawali w tych gajach heneckich tylko'
            ' symbole, „pojęcia o kraju bogów i o czasach rajskich”; przykład'
            ' litewski poucza zaś dostatecznie, że podanie to, jak tyle innych,'
            ' które najmylniej symbolicznie tłumaczą, należy rozumieć'
            ' dosłownie, o prawdziwych gajach i zwierzętach, nie o jakimś'
            ' raju i towarzyszach Adama; przesada w podaniu naturalnie razić'
            ' nie może. Badania mitologiczne byłyby już od dawna o wiele'
            ' głębiej dotarły, gdyby mania symbolizowania wszelkich'
            ' szczegółów, i dziś jeszcze nie wykorzeniona, nie odwracała ich'
            ' na manowce.\n-- Aleksander Brückner "Starożytna Litwa"'
        )
        msg = message.ChallengeSolution(solution=solution)
        expected = [
            ['solution', solution],
        ]
        self.assertEqual(expected, msg.slots())

    def test_no_payload_messages(self):
        for message_class in (
                message.Ping,
                message.Pong,
                message.GetPeers,
                message.GetTasks,
                message.GetResourcePeers,
                message.StopGossip,
        ):
            msg = message_class()
            expected = []
            self.assertEqual(expected, msg.slots())

    def test_list_messages(self):
        def obj_factory():
            return object()
        for message_class, key, factory in (
                (message.Peers, 'peers', dt_p2p_factory.Peer),
                (message.Tasks, 'tasks', dt_tasks_factory.TaskHeaderFactory),
                (message.ResourcePeers, 'resource_peers', obj_factory),
                (message.Gossip, 'gossip', obj_factory), ):
            msg = message_class()
            value = []
            expected = [
                [key, value]
            ]
            self.assertEqual(expected, msg.slots())

            value = [factory()]
            msg_kwarg = message_class(**{key: value})
            serialized_value = msg_kwarg.serialize_slot(key, value)
            expected = [
                [key, serialized_value]
            ]
            self.assertEqual(expected, msg_kwarg.slots())
            msg_slots = message_class(slots=[(key, serialized_value)])
            self.assertEqual(expected, msg_slots.slots())

    def test_int_messages(self):
        for message_class, key in (
                (message.Disconnect, 'reason'),
                (message.Degree, 'degree'), ):
            value = random.randint(-10**10, 10**10)
            msg = message_class(**{key: value})
            expected = [
                [key, value]
            ]
            self.assertEqual(expected, msg.slots())

    def test_uuid_messages(self):
        for message_class, key in (
                (message.RemoveTask, 'task_id',),
                (message.FindNode, 'node_key_id'),
                (message.StartSessionResponse, 'conn_id'),
                (message.HasResource, 'resource'),
                (message.WantsResource, 'resource'),
                (message.PullResource, 'resource'), ):
            value = 'test-{}'.format(uuid.uuid4())
            msg = message_class(**{key: value})
            expected = [
                [key, value]
            ]
            self.assertEqual(expected, msg.slots())

    def test_message_loc_rank(self):
        node_id = 'test-{}'.format(uuid.uuid4())
        loc_rank = random.randint(-10**10, 10**10)
        msg = message.LocRank(node_id=node_id, loc_rank=loc_rank)
        expected = [
            ['node_id', node_id],
            ['loc_rank', loc_rank]
        ]
        self.assertEqual(expected, msg.slots())

    def test_message_task_failure(self):
        ttc = factories.tasks.TaskToComputeFactory()
        err = (
            'Przesąd ten istnieje po dziś dzień u Mordwy, lecz już tylko '
            'symbol tego pozostał, co niegdyś dziki Fin w istocie tworzył.'
        )

        msg = message.TaskFailure(task_to_compute=ttc, err=err)
        expected = sorted([
            ['task_to_compute', helpers.single_nested(ttc)],
            ['reason', message.TaskFailure.REASON.ComputationError],
            ['err', err],
        ])
        self.assertEqual(expected, sorted(msg.slots()))

    def test_message_cannot_compute_task(self):
        ttc = factories.tasks.TaskToComputeFactory()
        reason = (
            "Opowiada Hieronim praski o osobliwszej czci, jaką w głębi Litwy"
            " cieszył się żelazny młot niezwykłej wielkości; „znaki zodiaka”"
            " rozbiły nim wieżę, w której potężny król słońce więził;"
            " należy się więc cześć narzędziu, co nam światło odzyskało."
            " Już Mannhardt zwrócił uwagę na kult młotów (kamiennych)"
            " na północy; młoty „Tora” (pioruna) wyrabiano w Skandynawii"
            " dla czarów jeszcze w nowszych czasach; znajdujemy po grobach"
            " srebrne młoteczki jako amulety; hr. Tyszkiewicz opowiadał,"
            " jak wysoko chłop litewski cenił własności „kopalnego” młota"
            " (zeskrobany proszek z wodą przeciw chorobom służył itd.)."
        )
        msg = message.CannotComputeTask(task_to_compute=ttc, reason=reason)
        expected = sorted([
            ['task_to_compute', helpers.single_nested(ttc)],
            ['reason', reason],
        ])
        self.assertEqual(expected, sorted(msg.slots()))

    def test_message_push(self):
        resource = 'test-r-{}'.format(uuid.uuid4())
        copies = random.randint(-10**10, 10**10)
        msg = message.PushResource(resource=resource, copies=copies)
        expected = sorted([
            ['resource', resource],
            ['copies', copies],
        ])
        self.assertEqual(expected, sorted(msg.slots()))

    def test_message_pull_answer(self):
        resource = 'test-r-{}'.format(uuid.uuid4())
        for has_resource in (True, False):
            msg = message.PullAnswer(
                resource=resource,
                has_resource=has_resource
            )
            expected = [
                ['resource', resource],
                ['has_resource', has_resource],
            ]
            self.assertEqual(expected, msg.slots())

    def test_message_remove_task_container(self):
        test_cases = 10
        task_ids = ['test-{}'.format(uuid.uuid4()) for _ in range(test_cases)]
        remove_tasks = [message.RemoveTask(task_id=task_ids[i])
                        for i in range(test_cases)]
        msg = message.RemoveTaskContainer(remove_tasks=remove_tasks)
        serialized = shortcuts.dump(msg, None, None)
        msg_l = shortcuts.load(serialized, None, None)

        expected = [
            ['remove_tasks', helpers.list_nested(remove_tasks)]
        ]
        self.assertEqual(expected, msg_l.slots())
        self.assertEqual(len(msg_l.remove_tasks), test_cases)
        for msg_remove_task in msg_l.remove_tasks:
            self.assertIsInstance(
                msg_remove_task,
                message.p2p.RemoveTask
            )
        for i in range(test_cases):
            self.assertEqual(msg_l.remove_tasks[i].task_id, task_ids[i])
