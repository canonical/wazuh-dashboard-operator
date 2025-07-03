# Wazuh Dasboard Operator
[![Charmhub](https://charmhub.io/wazuh-dashboard/badge.svg)](https://charmhub.io/wazuh-dashboard)
[![Release](https://github.com/canonical/wazuh-dashboard-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/wazuh-dashboard-operator/actions/workflows/release.yaml)
[![Tests](https://github.com/canonical/wazuh-dashboard-operator/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/canonical/wazuh-dashboard-operator/actions/workflows/ci.yaml)
[![Docs](https://github.com/canonical/wazuh-dashboard-operator/actions/workflows/sync_docs.yaml/badge.svg)](https://github.com/canonical/wazuh-dashboard-operator/actions/workflows/sync_docs.yaml)



[//]: # (<h1 align="center">)
[//]: # (  <a href="https://wazuh.com/">)
[//]: # (    <img src="https://wazuh.com/uploads/2022/05/WAZUH.png" alt="Wazuh" />)
[//]: # (  </a>)
[//]: # (  <br />)
[//]: # (</h1>)

# Description

[Wazuh Dashboard](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/)) 
is a frontend application that for visualizing data stored in an Wazuh Indexer
database. Charmed Wazuh Dashboard is the adaptation of the 
[Wazuh Dashboard](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/) 
user interface to the [Juju](https://juju.is/) environment.

The charm supports access via:

 - HTTPS (typically for direct access)
 - HTTP (load-balancing) 

![Wazuh Dashboard](./docs/opensearch_dashboard.png)

# Usage

## Pre-requisites

### Juju

Wazuh Dashboard is a Juju charm. This means that an existing Juju environment is necessary.

Install and initialize the [LXD](https://canonical.com/lxd) 
lightweight container hypervisor and Juju from the [Snap Store](https://snapcraft.io/store):

```shell
sudo snap install juju --classic --channel=3.1/stable
sudo snap install lxd
lxd init --auto
```
Then, boostrap Juju over LXD:
```shell
juju bootstrap localhost
```

### Charmed Wazuh Indexer

Wazuh Dashboard visualizes an underlying Wazuh database.
This means that a [Charmed Wazuh Indexer](https://charmhub.io/wazuh-indexer/)
instance also has to be ready and available.

A straightforward installation guide is available in the charm's 
[Github repository](https://github.com/canonical/wazuh-indexer-operator?tab=readme-ov-file#usage).


## Install Charmed Wazuh Dashboard

The Dashboards charm requires no specific environment adjustments.
Therefore all we need to do to deploy the charm from [Charmhub](https://charmhub.io/wazuh-dashboard) is 

```shell
juju deploy wazuh-dashboard --channel=4/edge
```
and integrate it with the Wazuh Indexer charm:
```shell
juju integrate wazuh wazuh-dashboard-operator
```

### Enable TLS encryption

Switching to TLS support for the Wazuh Dashboard charms goes identically to
how it goes for Wazuh.

Install the 
[self-signed-certificates operator](https://github.com/canonical/self-signed-certificates-operator)

```shell
juju deploy self-signed-certificates --channel=latest/stable
```
and integrate it with the Dashboards charm

```shell
juju integrate wazuh-dashboard self-signed-certificates
```

## Test interactive access

Functionality of the service can be tested by making an attempt to access the
portal either from the command-line or a web browser.

A few pieces of information are required to do this.

### URL

Construct the URL first.

The Dashboard front-end is exposed on port `5601`. Using `juju status` we can
retrieve the IP of each unit:

```shell
wazuh-dashboard/0*     active    idle   1        10.4.151.209              
```

Using the example above, the Dashboard URL is `http://10.4.151.209:5601`.


### Authentication

Set up a database user by deploying the `data-integrator` [charm](https://charmhub.io/data-integrator)
and integrating it with `wazuh-indexer`. The user is created automatically as a result of the integration.

```shell
$ juju deploy data-integrator
$ juju deploy data-integrator --config index-name=<index_name>
```

Retrieve user credentials running

```shell
juju run data-integrator/0 get-credentials
```
at the bottom of the output you should see something like:

```text
  password: 8kubD7nbWYZFHPVEzIVmTyqV42I7wHb4
  <CA certificate here>
  username: opensearch-client_15
```

## Access the Dashboard

Using information from above, the dashboard URI is construted as 

```text
https://<IP>:5601
```

Log in with the credentials of the new user.

![Wazuh Dashboard login](./docs/opensearch_dashboard_login.png)

You must create an "index pattern" that enables the Dasboard to access the user's data.
It should specify the `index_name` that was used to create the user with `data-integrator`.

Follow instructions from Wazuh documentation on 
[How to create an index pattern](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)

When the index pattern is defined, data that belongs to the user will display in the Dasboards.


# Contribute

`wazuh-dashboard-operator` is a fork of [`opensearch-dashboards-operator`](https://github.com/canonical/opensearch-dashboards-operator). If you're interested in adding non Wazuh specific features to the charm, consider contributing upstream.

The maintenance of the fork is documented in [CONTRIBUTING.fork.md](CONTRIBUTING.fork.md).

# License

The Charmed Wazuh Dashboard Operator is free software, distributed under the Apache
Software License, version 2.0. See [LICENSE](./LICENSE) for more information.

