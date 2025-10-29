FROM docker.elastic.co/beats/filebeat:8.13.0
USER root
RUN rm -f /usr/share/filebeat/filebeat.yml
COPY filebeat.yml /usr/share/filebeat/filebeat.yml