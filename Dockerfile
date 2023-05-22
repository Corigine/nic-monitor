FROM ubuntu:22.04 as builder

ENV PATH=$PATH:/usr/local/go/bin

RUN apt update && apt install git wget libftdi1 libjansson4 libusb-0.1-4 libusb-1.0-0 make gcc -y
RUN cd /usr/src/ && \
    wget https://golang.google.cn/dl/go1.19.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.19.3.linux-amd64.tar.gz && \
    rm -rf go1.19.3.linux-amd64.tar.gz && \
    go env -w GOPROXY="https://goproxy.cn,direct"

RUN wget https://download.corigine.com.cn/public/apt/pool/main/n/nfp-bsp-amd64/nfp-bsp_23.04-0.focal_amd64.deb && \
    dpkg -i nfp-bsp_23.04-0.focal_amd64.deb && \
    wget http://storage-01.nji.corigine.com/cloud/binaries/nfp-bsp/releases/deb/nfp-bsp-dev_23.04-0.focal_amd64.deb && \
    dpkg -i nfp-bsp-dev_23.04-0.focal_amd64.deb
RUN cd /usr/src && \
    git clone https://github.com/Corigine/nic-monitor.git && \
    cd nic-monitor && \
    make build-go
RUN cd /opt/netronome/lib/ && \
    rm -rf *.a

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

COPY --from=builder nfp-bsp_23.04-0.focal_amd64.deb /usr/src
COPY --from=builder /usr/src/nic-monitor/images/* /usr/local/bin

RUN cd /usr/src && \
    apt update && \
    apt install libjansson4 libftdi1 libusb-0.1-4 libusb-1.0-0 -y --no-install-recommends && \
    dpkg -i nfp-bsp_23.04-0.focal_amd64.deb && \
    rm -rf /opt/netronome/flash && \
    rm -rf /opt/netronome/drv && \
    rm -rf nfp-bsp_23.04-0.focal_amd64.deb && \
    rm -rf /var/lib/apt/lists/*

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/netronome/lib

