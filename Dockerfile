FROM debian:buster-slim
#ARG RUSTY_VERSION=1.0.10
#ARG ARCHITECTURE=musl
RUN apt-get update && apt-get install -y openssl openssh-client ca-certificates wget unzip python3-pip git jq vim
RUN mkdir -p /opt/dss
#RUN cd /opt/hogs && wget https://github.com/newrelic/rusty-hog/releases/download/v${RUSTY_VERSION}/rustyhogs-${ARCHITECTURE}-choctaw_hog-${RUSTY_VERSION}.zip && unzip rustyhogs-${ARCHITECTURE}-choctaw_hog-${RUSTY_VERSION}.zip
#COPY certificates/* /usr/local/share/ca-certificates
COPY src/ /opt/dss
RUN cd /opt/dss; pip3 install -r requirements.txt
#RUN chmod 644 /usr/local/share/ca-certificates/* && update-ca-certificates
#RUN curl https://cli-assets.heroku.com/install-ubuntu.sh | sh
#ENV PATH "$PATH:/opt/hogs/${ARCHITECTURE}_releases"

EXPOSE 5000

WORKDIR /opt/dss
#ENTRYPOINT ["/usr/local/bin/gunicorn app:app"]
#ENTRYPOINT ["bash"]
CMD ["gunicorn"  , "-b", "0.0.0.0:5000", "app:app"]
