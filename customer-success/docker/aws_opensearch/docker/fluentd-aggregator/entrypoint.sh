#!/bin/bash

sed -ri "s/FLUENTD_SECRET/${FLUENTD_SECRET}/g" /etc/td-agent/td-agent.conf
sed -ri "s/ES_HOST/${ES_HOST}/g" /etc/td-agent/td-agent.conf
systemctl restart td-agent

exec "$@"
