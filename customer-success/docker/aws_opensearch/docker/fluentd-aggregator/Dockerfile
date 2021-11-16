FROM ubuntu:focal

LABEL maintainer=ted.dong@chaossearch.com

ENV FLUENTD_SECRET some-secret
ENV ES_HOST odfe-node1

RUN \
  apt-get update && \
  apt-get install -y curl sudo ruby-full gnupg vim systemctl make libcurl4-gnutls-dev build-essential && \
  curl -L http://toolbelt.treasuredata.com/sh/install-ubuntu-focal-td-agent4.sh | sh && \
  /usr/sbin/td-agent-gem install fluent-plugin-secure-forward && \
  /usr/sbin/td-agent-gem install fluent-plugin-elasticsearch && \
  mv /etc/td-agent/td-agent.conf /etc/td-agent/td-agent.conf.original

COPY td-agent.conf /etc/td-agent/td-agent.conf
COPY entrypoint.sh /root/entrypoint.sh

ENTRYPOINT ["/root/entrypoint.sh"]
CMD ["bash"]

