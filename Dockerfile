FROM debian:8.8
RUN apt-get update && \
    apt-get install -y libpam0g:amd64 \
    libpam0g-dev:amd64 wget tar build-essential && \
    rm -rf /var/lib/apt/lists/* && \
    wget https://storage.googleapis.com/golang/go1.8.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.8.3.linux-amd64.tar.gz && \
    rm -f go1.8.3.linux-amd64.tar.gz && \
    ln -sf /usr/local/go/bin/go /usr/bin/go
ENV GOPATH=/usr/local/go
