FROM ghcr.io/emqx/emqx-builder/5.3-9:1.15.7-26.2.5-3-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root
ENV TERM=xterm-256color

RUN apt update && apt install net-tools
ADD . /gen_rpc
WORKDIR "/gen_rpc"
RUN make
