(dashboard-how-to-change-credentials)=
# Change credentials

Dashboards have a “super-user” called `kibanaserver`, that is a built-in user
set in the Opensearch database.

For this reason, the credentials change doesn’t happen on the Dashboards side,
rather on the Opensearch side.

Running the following command on the leader unit changes the `kibanaserver` password:

```shell
juju run openserach/0 set-password
```

The new credentials will be populated for the Dashboards charm.

## Wazuh API credentials

The Wazuh API credentials supplied by the Wazuh Server over the `wazuh-api`
integration are separate from OpenSearch's `kibanaserver` credentials.
Manage them on the Wazuh Server side, not by editing the dashboard configuration.

When the server updates the credentials secret, the dashboard retrieves its
latest revision and updates `wazuh.yml`. Relation updates and dashboard
initialization also retrieve the latest credentials; recreating the integration
is not required for rotation.

If the published data is incomplete, invalid, or the secret cannot be accessed,
the dashboard preserves its existing configuration. Inspect `juju debug-log`
for Wazuh API diagnostics. A subsequent credential-secret change, relation
update, or dashboard initialization retries the configuration update.
This describes configuration-file propagation, not a guarantee that the running
Wazuh plugin immediately reloads its credentials.
