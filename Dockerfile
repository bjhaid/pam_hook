FROM debian:stretch
ADD pam_hook /usr/bin/pam_hook
RUN apt-get update && \
    env DEBIAN_FRONTEND=noninteractive \
    apt-get install -y libpam0g:amd64 libpam0g-dev:amd64
