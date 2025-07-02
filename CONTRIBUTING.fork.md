# How to maintain the fork

> [!IMPORTANT]
> GitHub wrongly shows that the fork is based on the `main` branch of `opensearch-dashboards-operator`.
> `wazuh-dashboard-operator` is based on the `2/edge` branch.

## Prepare

- Clone the repository if you don't already have it.
- Prepare your working branch: `git checkout -b chore/merge_upstram`
- Ensure that all CI tests pass before changing anything. You can trigger the CI with an empty commit: `git commit --allow-empty -m 'Trigger CI' && git push -u origin chore/merge_upstram`.
- Fetch upstream branch:

```shell
git remote add upstream https://github.com/canonical/opensearch-dashboards-operator.git
git fetch upstream
```

## Merge

Start the merge with `git merge upstream/2/edge`.

During the merge, you will face three potential conflicts:
- You may want to keep the local version of a file, then use: `git checkout --ours <the-file>`
- You may want to keep the upstream version of a file, then use: `git checkout --their <the-file>`
- The file has to be manually edited to keep changes from both.

Once you have fixed the conflict, `git add` the file and move to the next one.
