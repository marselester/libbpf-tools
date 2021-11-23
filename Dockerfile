FROM ubuntu:groovy as build
RUN apt-get update && \
    apt-get install -y clang wget && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN wget https://golang.org/dl/go1.17.3.linux-amd64.tar.gz -qO /tmp/go.tar.gz && \
    echo '550f9845451c0c94be679faf116291e7807a8d78b43149f9506c1b15eb89008c /tmp/go.tar.gz' | sha256sum -c - && \
    tar -xzf /tmp/go.tar.gz -C /usr/local
WORKDIR /opt/libbpf-tools/
COPY . /opt/libbpf-tools/
RUN /usr/local/go/bin/go build -o . ./cmd/...

FROM ubuntu:groovy
RUN apt-get update && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /opt/libbpf-tools/
COPY --from=build \
    /opt/libbpf-tools/execsnoop \
    /opt/libbpf-tools/tcpconnect \
    /opt/libbpf-tools/tcpconnlat \
    /opt/libbpf-tools/tcplife \
    ./
