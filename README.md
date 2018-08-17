# golem-messages

[![CircleCI](https://circleci.com/gh/golemfactory/golem-messages.svg?style=shield)](https://circleci.com/gh/golemfactory/golem-messages)
[![codecov](https://codecov.io/gh/golemfactory/golem-messages/branch/master/graph/badge.svg)](https://codecov.io/gh/golemfactory/golem-messages)

Shared module for formatting and parsing messages for Golem and Concent.

Includes a library of all message types used by Golem client and by the Concent
Service. 

* **Deprecation Warning:** using message class imports from the root `message`
module is now deprecated and will be removed soon - please use imports from
their respective modules - e.g. `base`, `tasks`, `concents`...

