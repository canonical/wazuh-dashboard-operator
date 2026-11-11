(dashboard-how-to-upgrade)=
# How to perform an upgrade

The `wazuh-dashboard` charm is stateless, but its workload snap is held on a pinned revision.
Before upgrading or refreshing the charm, run the `pre-upgrade-check` action on the leader unit.
The action validates that the workload is running and creates the upgrade stack that
`juju refresh` uses to coordinate the upgrade.

```{note}
Always run `pre-upgrade-check` before `juju refresh`. Refreshing without the upgrade stack leaves
the workload snap on its previous revision, and the dashboard can report an API version mismatch.
```

## Run the pre-upgrade check

Run the action on the leader unit:

```shell
juju run wazuh-dashboard/leader pre-upgrade-check
```

Wait for the action to complete and confirm that it succeeded. If the action fails, resolve the
reported problem before continuing.

## Refresh the charm

```shell
juju refresh wazuh-dashboard --channel=<channel>
```

## Verify the upgrade

Check the application status and the snap revision on each unit:

```shell
juju status
juju ssh wazuh-dashboard/0 -- snap list wazuh-dashboard
```

The snap should match the revision pinned by the new charm revision and be marked as held.

## Recover from a failed upgrade

If a unit fails during the upgrade, run `pre-upgrade-check` on the leader unit again to enter
recovery, then refresh back to the previous revision:

```shell
juju run wazuh-dashboard/leader pre-upgrade-check
juju refresh wazuh-dashboard --revision=<previous-revision>
```
