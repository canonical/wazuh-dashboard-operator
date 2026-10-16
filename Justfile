# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

[private]
default:
    @just --list --unsorted

[group('Setup')]
install-requirements:
    uv tool install tox
    uv tool install poetry
    uv tool install prek
    prek install

[group('Testing & Quality Assurance')]
lint:
    tox run -e lint

[group('Testing & Quality Assurance')]
static:
    tox run -e static

[group('Testing & Quality Assurance')]
test *args:
    tox run -e unit -- {{args}}

[group('Testing & Quality Assurance')]
test-integ *args:
    tox run -e integration -- {{args}}

[group('Operations & Deployment')]
ops:
    charmcraft pack
