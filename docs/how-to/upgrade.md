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

The `snap list` output should look similar to this:

```text
Name             Version  Rev  Tracking   Publisher      Notes
wazuh-dashboard  4.14.7   15   4.14/edge  arturo-seijas  held
```

Check the following:

- `Rev` matches the snap revision pinned by the refreshed charm
  (`OPENSEARCH_DASHBOARDS_SNAP_REVISION`). The exact value changes between charm revisions.
- `Tracking` matches the snap channel pinned by the refreshed charm
  (`OPENSEARCH_DASHBOARDS_SNAP_CHANNEL`).
- `Notes` contains `held`, which prevents snapd from refreshing the snap outside the
  charm's control.
- The charm's channel track and the snap's `Tracking` track match. For example, a charm
  from the `4.14/stable` channel must run a snap tracking the `4.14` track. If the charm
  is on the `4.14` track but the snap still tracks `4.11/edge`, the upgrade did not
  complete.

## Recover from a failed upgrade

If a unit fails during the upgrade, run `pre-upgrade-check` on the leader unit again to enter
recovery, then refresh back to the previous revision:

```shell
juju run wazuh-dashboard/leader pre-upgrade-check
juju refresh wazuh-dashboard --revision=<previous-revision>
```

If the failure involves the Wazuh indexer or the OpenSearch cluster, follow the
[Charmed OpenSearch upgrade, rollback, and recovery guide](https://canonical.com/data/opensearch/docs/latest/how-to/upgrade/).
