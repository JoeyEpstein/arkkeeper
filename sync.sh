#!/usr/bin/env bash
set -e
git pull --rebase
git push origin "$(git rev-parse --abbrev-ref HEAD)"
