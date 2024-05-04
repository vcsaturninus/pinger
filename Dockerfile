FROM python:3 as base

RUN apt update && apt-get -y install \
ncat \
iproute2 \
iputils-ping

ARG TOPDIR=/home/
COPY agent.py $TOPDIR
COPY run_agent.sh $TOPDIR

ENV SERVER_ADDR=
ENV SERVER_PORT=
ENV L4PROTO_FLAG=
ENV mode=

WORKDIR $TOPDIR
CMD ./run_agent.sh
