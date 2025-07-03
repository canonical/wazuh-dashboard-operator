# How to maintain the fork

> [!IMPORTANT]
> GitHub incorrectly shows that the fork is based on the `main` branch of `opensearch-dashboards-operator`.
> `wazuh-dashboard-operator` is based on the `2/edge` branch.

## Prepare

- Clone the repository: `git clone https://github.com/canonical/wazuh-dashboard-operator.git`
- Prepare your working branch: `git checkout -b chore/merge_upstram`
- Ensure that all CI tests pass before changing anything. You can trigger the CI with an empty commit: `git commit --allow-empty -m 'Trigger CI' && git push -u origin chore/merge_upstram`.
- Fetch the upstream branch:

```shell
git remote add upstream https://github.com/canonical/opensearch-dashboards-operator.git
git fetch upstream
```

## Merge

Start the merge with `git merge upstream/2/edge`.

During the merge, you will face three potential conflicts:
- If you want to keep the local version of a file, then use: `git checkout --ours <the-file>`
- If you want to keep the upstream version of a file, then use: `git checkout --their <the-file>`
- If you want to keep changes from both versions, manually edit the file.

Once you have fixed the conflict, run the following command to add the file to the staging area and move to the next one: `git add <file_name>`
