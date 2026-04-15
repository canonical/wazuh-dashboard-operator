# Sync Upstream Learnings

Lessons learned from each sync cycle, to avoid repeating the same mistakes.

---

## Sync: upstream/2/edge into chore/sync-upstream-2.19.4 (April 2026)

### 1. RST-style labels need blank lines before headings (MD022)

Upstream MyST/Sphinx docs use `(label-name)=` targets at the top of files (and before section headings) immediately followed by `# Heading` with no blank line. The pymarkdownlnt `blanks-around-headings` rule (MD022) treats the label as a paragraph and requires a blank line between it and the following heading.

**Fix**: Add a blank line after each `(label)=` pattern before a `#` heading. A one-liner Python script can batch-fix all docs files:
```python
re.sub(r'(\([a-z0-9_-]+\)=)\n(#)', r'\1\n\n\2', text)
```

**Caveat**: Also check for headings sandwiched between HTML comments (e.g., Vale comments) — pymarkdown requires blank lines on both sides of every heading, and HTML comments do not count as blank lines.

### 2. pymarkdownlnt `--exclude` does not support recursive path prefix matching

The upstream Makefile `lint-md` target uses `--exclude=./.sphinx/**` to skip the Sphinx venv. In pymarkdownlnt 0.9.36, this glob is not expanded recursively — the venv's third-party README files get scanned and fail the linter.

**Fix**: Instead of scanning all of `$(SOURCEDIR)` and trying to exclude the venv, explicitly pass the directories you want to lint: `how-to/ tutorial/ reference/ index.md`. This is more robust and avoids any glob-expansion ambiguity.

### 3. Sphinx `document isn't included in any toctree` warnings break CI

The upstream docs migration adds `tutorial/`, `how-to/`, and `reference/` subdirectories. Our Wazuh-specific `docs/index.md` was kept from the fork (no `{toctree}` directive), causing those docs to be "orphaned" — Sphinx warns and the build fails with `--fail-on-warning`.

**Fix**: Add a `{toctree}` block to `docs/index.md` that includes the upstream doc sections (`tutorial/index`, `how-to/index`, `reference/index`). Also add any Wazuh-specific docs (e.g., `how-to/upgrade`) to the appropriate toctree so they aren't orphaned.

### 4. `check-removed-urls` workflow breaks when base branch lacks `make install`

The `check-removed-urls.yml` workflow builds docs from both the PR branch and the base branch (`main`) to compare URLs. When the PR introduces new docs infrastructure (the `make install` Makefile target), the base branch doesn't have it yet and the loop fails.

**Fix**: Wrap the base branch build in a conditional so it fails gracefully:
```bash
if make install; then
  . .sphinx/venv/bin/activate && make html || true
else
  echo "Skipping base build — new docs infrastructure"
  mkdir -p _build
fi
```
This is a one-time bootstrapping problem; once the PR is merged, future PRs will work normally.

### 5. `matrix.to` links return 451 in CI (GDPR/legal block)

The `linkcheck` step in `automatic-doc-checks.yml` uses Sphinx's linkchecker. `matrix.to` links return HTTP 451 (Unavailable For Legal Reasons) in some CI environments. This is a transient, environment-specific block, not an actual broken link.

**Fix**: Add `r"https://matrix\.to/.*"` as a regex entry in `linkcheck_ignore` in `docs/conf.py` to skip all matrix.to URLs. The upstream conf.py only ignored one specific channel; broaden it to cover all matrix.to links.

### 6. Fork must have a `CONTRIBUTING.md` if docs link to it

`docs/index.md` links to `https://github.com/canonical/wazuh-dashboard-operator/blob/main/CONTRIBUTING.md`. The file did not exist in the fork, causing a 404 in the linkcheck.

**Fix**: Create a minimal `CONTRIBUTING.md` at the repo root pointing to the upstream contributing guide. Do not just remove the link — the file should exist for any project that accepts contributions.

### 7. Double blank lines before headings also fail MD022

MD022 (`blanks-around-headings`) enforces exactly 1 blank line above/below headings, not ≥ 1. A heading preceded by 2 blank lines (`Actual: 2; Above`) is also a violation. Clean up any double blank lines before headings in fork-specific markdown files.

### 8. GitHub URLs return 502 in Sphinx linkchecker (rate limiting)

Sphinx `linkcheck` sends many HTTP requests to GitHub in rapid succession. GitHub responds with 502 Bad Gateway after rate limiting, even with `linkcheck_retries = 3`. The `linkcheck_anchors_ignore_for_url` setting (already in the upstream conf.py) only skips anchor validation — the URL itself is still fetched and fails.

**Fix**: Add `r"https://github\.com/.*"` to `linkcheck_ignore` in `conf.py`. This skips all GitHub URL validation in CI. It is a pragmatic trade-off: GitHub links are generally reliable and developer-visible, so the cost of skipping the CI check is low compared to the flakiness introduced by rate limiting.

---

- After importing upstream docs, always run `make lint-md` locally before pushing.
- After updating `docs/index.md` or toctrees, run `make html` locally with `--fail-on-warning`.
- Check `linkcheck_ignore` in `conf.py` covers all fork-specific external links.
- Any file linked from docs must actually exist in the fork (CONTRIBUTING.md, SECURITY.md, etc.).
