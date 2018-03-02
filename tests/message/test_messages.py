import os
import random
import time
import unittest
import unittest.mock as mock
import uuid

from golem_messages import datastructures
from golem_messages import message
from golem_messages import shortcuts


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
        node_name = 'Tuż nad Bugiem, z lewej strony,'
        msg = message.Hello(node_name=node_name)
        self.assertEqual(msg.node_name, node_name)

    def test_slot(self):
        node_name = 'Tuż nad Bugiem, z lewej strony,'
        msg = message.Hello(slots=[('node_name', node_name), ])
        self.assertEqual(msg.node_name, node_name)

    def test_kwarg_and_slot(self):
        node_name_kwarg = 'Tuż nad Bugiem, z lewej strony,'
        node_name_slot = 'Stoi wielki bór zielony.'
        msg = message.Hello(
            node_name=node_name_kwarg,
            slots=[('node_name', node_name_slot), ],
        )
        self.assertEqual(msg.node_name, node_name_slot)


class MessagesTestCase(unittest.TestCase):
    def test_message_want_to_compute_task(self):
        node_id = 'test-ni-{}'.format(uuid.uuid4())
        task_id = 'test-ti-{}'.format(uuid.uuid4())
        perf_index = random.random() * 1000
        price = random.random() * 1000
        max_resource_size = random.randint(1, 2**10)
        max_memory_size = random.randint(1, 2**10)
        num_cores = random.randint(1, 2**5)
        msg = message.WantToComputeTask(
            node_name=node_id,
            task_id=task_id,
            perf_index=perf_index,
            price=price,
            max_resource_size=max_resource_size,
            max_memory_size=max_memory_size,
            num_cores=num_cores)
        expected = [
            ['node_name', node_id],
            ['task_id', task_id],
            ['perf_index', perf_index],
            ['max_resource_size', max_resource_size],
            ['max_memory_size', max_memory_size],
            ['num_cores', num_cores],
            ['price', price],
        ]
        self.assertEqual(expected, msg.slots())

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
        msg_pre = message.Hello(header=datastructures.MessageHeader(
            message.Hello.TYPE,
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
                message.WaitingForResults, ):
            msg = message_class()
            expected = []
            self.assertEqual(expected, msg.slots())

    def test_list_messages(self):
        for message_class, key in (
                (message.Peers, 'peers'),
                (message.Tasks, 'tasks'),
                (message.ResourcePeers, 'resource_peers'),
                (message.Gossip, 'gossip'), ):
            msg = message_class()
            value = []
            expected = [
                [key, value]
            ]
            self.assertEqual(expected, msg.slots())

            value = [object()]
            msg_kwarg = message_class(**{key: value})
            expected = [
                [key, value]
            ]
            self.assertEqual(expected, msg_kwarg.slots())
            msg_slots = message_class(slots=[(key, value)])
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

    def test_message_want_to_start_task_session(self):
        node_info = 'test-ni-{}'.format(uuid.uuid4())
        conn_id = 'test-ci-{}'.format(uuid.uuid4())
        super_node_info = 'test-sni-{}'.format(uuid.uuid4())
        msg = message.WantToStartTaskSession(
            node_info=node_info,
            conn_id=conn_id,
            super_node_info=super_node_info
        )
        expected = [
            ['node_info', node_info],
            ['conn_id', conn_id],
            ['super_node_info', super_node_info],
        ]
        self.assertEqual(expected, msg.slots())

    def test_message_set_task_session(self):
        key_id = 'test-ki-{}'.format(uuid.uuid4())
        node_info = 'test-ni-{}'.format(uuid.uuid4())
        conn_id = 'test-ci-{}'.format(uuid.uuid4())
        super_node_info = 'test-sni-{}'.format(uuid.uuid4())
        msg = message.SetTaskSession(
            key_id=key_id,
            node_info=node_info,
            conn_id=conn_id,
            super_node_info=super_node_info
        )
        expected = [
            ['key_id', key_id],
            ['node_info', node_info],
            ['conn_id', conn_id],
            ['super_node_info', super_node_info],
        ]
        self.assertEqual(expected, msg.slots())

    def test_message_get_resource(self):
        task_id = 'test-ti-{}'.format(uuid.uuid4())
        resource_header = 'test-rh-{}'.format(uuid.uuid4())
        msg = message.GetResource(
            task_id=task_id,
            resource_header=resource_header
        )
        expected = [
            ['task_id', task_id],
            ['resource_header', resource_header],
        ]
        self.assertEqual(expected, msg.slots())

    def test_message_delta_parts(self):
        task_id = 'test-ti-{}'.format(uuid.uuid4())
        delta_header = 'test-dh-{}'.format(uuid.uuid4())
        parts = ['test-p{}-{}'.format(x, uuid.uuid4()) for x in range(10)]
        node_name = 'test-nn-{}'.format(uuid.uuid4())
        node_info = 'test-ni-{}'.format(uuid.uuid4())
        address = '8.8.8.8'
        port = random.randint(0, 2**16) + 1
        msg = message.DeltaParts(
            task_id=task_id,
            delta_header=delta_header,
            parts=parts,
            node_name=node_name,
            node_info=node_info,
            address=address,
            port=port)
        expected = [
            ['task_id', task_id],
            ['delta_header', delta_header],
            ['parts', parts],
            ['node_name', node_name],
            ['address', address],
            ['port', port],
            ['node_info', node_info],
        ]
        self.assertEqual(expected, msg.slots())

    def test_message_task_failure(self):
        subtask_id = 'test-si-{}'.format(uuid.uuid4())
        err = (
            'Przesąd ten istnieje po dziś dzień u Mordwy, lecz już tylko '
            'symbol tego pozostał, co niegdyś dziki Fin w istocie tworzył.'
        )

        msg = message.TaskFailure(subtask_id=subtask_id, err=err)
        expected = sorted([
            ['subtask_id', subtask_id],
            ['err', err],
            ['task_to_compute', None],
        ])
        self.assertEqual(expected, sorted(msg.slots()))

    def test_message_cannot_compute_task(self):
        subtask_id = 'test-si-{}'.format(uuid.uuid4())
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
        msg = message.CannotComputeTask(subtask_id=subtask_id, reason=reason)
        expected = sorted([
            ['reason', reason],
            ['subtask_id', subtask_id],
            ['task_to_compute', None],
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

    def test_message_resource_list(self):
        resources = 'test-rs-{}'.format(uuid.uuid4())
        options = 'test-clientoptions-{}'.format(uuid.uuid4())
        msg = message.ResourceList(resources=resources, options=options)
        expected = [
            ['resources', resources],
            ['options', options],
        ]
        self.assertEqual(expected, msg.slots())
