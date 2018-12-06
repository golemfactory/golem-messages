# pylint: disable=too-few-public-methods

import factory

from golem_messages.datastructures import tasks as dt_tasks
from golem_messages.factories import helpers
from golem_messages.factories.datastructures import p2p as dt_p2p_factories


class TaskHeader(factory.Factory):
    class Meta:
        model = dt_tasks.TaskHeader

    task_id = factory.LazyFunction(lambda: helpers.fake_golem_uuid('00adbeef' + 'deadbeef' * 15))
    task_owner = factory.LazyFunction(lambda: dt_p2p_factories.Node().to_dict())
    subtasks_count = factory.Faker('random_int', min=1)
    min_version = factory.LazyFunction(helpers.fake_version)
