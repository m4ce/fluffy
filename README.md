# Fluffy - A Firewall as a Service

Fluffy is a firewall as a service solution that primarily targets Linux environments.

## Features

* A fully documented RESTful API using Flasgger
* Session based configuration so that changes can be tested and committed atomically without affecting the active configuration
* Rollback methods using unattended server-side checks including rollback intervals with a *commit/confirm* type of functionality
* Source and destination addresses are managed by a global *addressbook* which also supports inheritance
* Source and destination services are managed by a global *services catalog*
* Chains support including default policy, packet matching tables etc.
* Interfaces support

## Puppet integration

A module is available on [PuppetForge](https://forge.puppet.com/m4ce/fluffy).

## Running in Docker

```
$ docker pull m4ce/fluffy
```

The container needs to run in privileged mode (--privileged). Additionally, you will need to make sure the Docker daemon is started with `--iptables=false`.

## Author
Matteo Cerutti - matteo.cerutti@hotmail.co.uk
