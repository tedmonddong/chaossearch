FROM docker.elastic.co/elasticsearch/elasticsearch:7.10.1

LABEL maintainer=ted.dong@chaossearch.com

RUN \
  cd /usr/share/elasticsearch && \
  bin/elasticsearch-keystore create && \
  printf "https://hooks.slack.com/services/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" | bin/elasticsearch-keystore add xpack.notification.slack.account.monitoring.secure_url

COPY elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml


