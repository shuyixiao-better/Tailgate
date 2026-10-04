#!/bin/sh
set -eu

mkdir -p /tmp/tailgate-fixtures
printf 'alpha\nBeta ERROR\nplain\nerror second\nlast-no-newline' > /tmp/tailgate-fixtures/sample.log
printf 'ERROR literal filename\n' > "/tmp/tailgate-fixtures/quoted ' name;\$(echo bad).log"
printf 'hidden content\n' > /tmp/tailgate-fixtures/.hidden
printf 'live initial\n' > /tmp/tailgate-fixtures/live.log
chown -R "${USER_NAME}:users" /tmp/tailgate-fixtures
chmod 0755 /tmp/tailgate-fixtures

# Force a real password-required sudo challenge, rather than the base image's
# optional NOPASSWD mode. Only this isolated development container is affected.
printf 'Defaults env_reset\nDefaults !requiretty\nroot ALL=(ALL:ALL) ALL\n%s ALL=(ALL:ALL) ALL\n' "$USER_NAME" > /etc/sudoers
chmod 0440 /etc/sudoers
printf '%s\n' "$USER_PASSWORD" > /run/tailgate-test-password
chmod 0600 /run/tailgate-test-password
