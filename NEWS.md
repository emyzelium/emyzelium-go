Version 0.9.10 (2024.02.02)
--------------------------

* Renamed `InConnectionsNum()` of Efunguz to `InAbsorbingNum()`

* Added related getters to Efunguz: `InPermittedNum()` (count of incoming connections that passed handshake *up to now*) and `InAttemptedNum()` (count of attempted incoming connections up to now), using socket monitor as well

At almost any instant, `Absorbing` ≤ `Permitted` ≤ `Attempted`.


Version 0.9.8 (2024.01.08)
--------------------------

* Added, via socket monitor, the counter of current accepted incoming connections = the number of authorised subscribers = "popularity", and corresponding `InConnectionsNum()` getter to Efunguz


Version 0.9.6 (2023.11.30)
--------------------------

* Replaced `zmq_poll(socket, …)` by `zmq_getsockopt(socket, ZMQ_EVENTS, …)`


Version 0.9.4 (2023.10.31)
--------------------------

* Initial release of Go version