FROM ubuntu:focal

LABEL maintainer=ted.dong@chaossearch.com

ENV FLUENTD_SECRET some-secret

RUN \
  apt-get update && \
  apt-get install -y curl sudo ruby-full gnupg vim rsyslog systemctl debconf-utils uuid-runtime && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q apache2 && \
  curl -L http://toolbelt.treasuredata.com/sh/install-ubuntu-focal-td-agent4.sh | sh && \
  /usr/sbin/td-agent-gem install fluent-plugin-secure-forward && \
  chmod og+rx /var/log/apache2 && \
  chmod og+r /var/log/apache2/* && \
  mv /etc/td-agent/td-agent.conf /etc/td-agent/td-agent.conf.original && \
  echo "*.* @127.0.0.1:42185" >> /etc/rsyslogd.conf && \
  systemctl restart rsyslog

COPY td-agent.conf /etc/td-agent/td-agent.conf
COPY entrypoint.sh /root/entrypoint.sh
COPY submit_log_entries.sh /root/submit_log_entries.sh

ENTRYPOINT ["/root/entrypoint.sh"]
CMD ["bash"]

