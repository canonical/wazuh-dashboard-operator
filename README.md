# OpenSearch Dasboards Operator
[![Charmhub](https://charmhub.io/opensearch/badge.svg)](https://charmhub.io/opensearch)
[![Release](https://github.com/canonical/opensearch-dashboards-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/opensearch-dashboards-operator/actions/workflows/release.yaml)
[![Tests](https://github.com/canonical/opensearch-dashboards-operator/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/canonical/opensearch-dashboards-operator/actions/workflows/ci.yaml)
[![Docs](https://github.com/canonical/opensearch-dashboards-operator/actions/workflows/sync_docs.yaml/badge.svg)](https://github.com/canonical/opensearch-dashboards-operator/actions/workflows/sync_docs.yaml)



[//]: # (<h1 align="center">)
[//]: # (  <a href="https://opensearch.org/">)
[//]: # (    <img src="https://opensearch.org/assets/brand/PNG/Logo/opensearch_logo_default.png" alt="OpenSearch" />)
[//]: # (  </a>)
[//]: # (  <br />)
[//]: # (</h1>)

# Description


[Opensearch Dashboards](https://opensearch.org/docs/latest/dashboards/) 
is a frontend application that lets you visualize data stored in an Opensearch
database. Charmed Opensearch Dashboard is the adaptation of the 
[Opensearch Dashboards](https://opensearch.org/docs/latest/dashboards/) 
user interface to the [Juju](https://juju.is/) environment.

The charm supports access via:

 - HTTPS (typically for direct access)
 - HTTP (load-balancing) 

![Opensearch Dashboards](./docs/opensearch_dashboard.png)

# Usage

## Pre-requisites

### Juju

Opensearch Dashboard is a Juju charm. Which means that an existing Juju environment is necessary.

Install and initialize the [LXD](https://canonical.com/lxd) 
lightweight container hypervisor and Juju from the [Snap Store](https://snapcraft.io/store):

```
sudo snap install juju --classic --channel=3.1/stable
sudo snap install lxd
lxd init --auto
```
Then boostrap Juju over LXD:
```
juju bootstrap localhost
```


### Opensearch

Opensearch Dashboards is visualizing an underlying Opensearch database. 
Which means that a [Charmed Opensearch](https://charmhub.io/opensearch/)
instance also has to be ready and available.

A straightforward installation guide is available in the charm's 
[Github repository](https://github.com/canonical/opensearch-operator?tab=readme-ov-file#usage):



## Opensearch Dashboards charm installation

The Dashboards charm requires no specific environment adjustments.
Therefore all we need to do to deploy the charm from [Charmhub](https://charmhub.io/opensearch-dashboards)

```
juju deploy openserach-dashboards --channel=2/edge
```
and relate it to the Opensearch charm:
```
juju relate opensearch opensearch-dashboards-operator
```

## Testing interactive access

Functionality of the service can be tested by making an attempt to access the
portal either from the command-line or a web browser.

A few pieces of information are required to do this.

### URL

Construct the URL first.

The Dashboard front-end is exposed on port `5601`. Using `juju status` we can
retrieve the IP of each unit:

```
opensearch-dashboards/0*     active    idle   1        10.4.151.209              
```

Using the example, the Dashboard URL is `http://10.4.151.209:5601`.

### Authentication

There is a pre-defined user Opensearch dedicated to Opensearch Dashboards access
called `kibanaserver`. Even on an empty Charmed Opensearch database the `kibanaserver`
user will be present and available to test Dashboards connection.

The following command displays the current `kibanaserver` password.

```
juju run opensearch/0 get-password username=kibanaserver
```

### TLS encryption

Switching to TLS support for the Opensearch Dashboards charms goes identical to
how it goes for Opensearch.

Install the 
[self-signed-certificats Operator](https://github.com/canonical/self-signed-certificates-operator)

```
juju deploy self-signed-certificates --channel=latest/stable
```
and relate it to the Dashboards charm

```
juju relate opensearch-dashboards self-sigend-certificates
```

## Accessing the Dashboard

Now all we either open the URL in a browser, or access the Dashboard from the command line.

For the latter, fetch the certificate file from the Dashboard (to pass certificate verificaton).

```
juju scp opensearch-dashboards/0:/var/snap/opensearch-dashboards/current/etc/opensearch-dashboards/certificates/ca.pem ./
```

Now issue the following `curl` command:

```
curl -XPOST https://<IP>:5601/auth/login -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'osd-xsrf:true' \
-d '{"username":"kibanaserver","password":"<PW>"}' --cacert ca.pem
```

The output should look like this 

```
{"username":"kibanaserver","tenants":{"kibanaserver":true},"roles":["own_index","kibana_server"],"backendroles":[]}
```

In case of a browser, a successful login is expected.

![Opensearch Dashboards login](./docs/opensearch_dashboard_login.png)

# License

The Charmed Opensearch Dashboards Operator is free software, distributed under the Apache
Software License, version 2.0. See [LICENSE](./LICENSE) for more information.

