FROM python:3.5-alpine

RUN apk add --no-cache openssl ca-certificates

RUN pip3 install --no-cache-dir requests pyyaml

ADD app /usr/src/app

WORKDIR /usr/src/app
VOLUME /usr/src/app/config
CMD /usr/src/app/daemon.sh
