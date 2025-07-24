FROM ubuntu:20.04

ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV HTTP_PROXY=${HTTP_PROXY}
ENV HTTPS_PROXY=${HTTPS_PROXY}

ARG DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn
# Update Ubuntu Software repository
RUN apt update && \
    apt-get install -y \
      git autoconf automake libtool make libreadline-dev texinfo \
      pkg-config libpam0g-dev libjson-c-dev bison flex python3-pip \
      libc-ares-dev python3-dev python3-sphinx \
      install-info build-essential libsnmp-dev perl \
      libcap-dev python2 libelf-dev \
      sudo gdb curl iputils-ping time \
      lua5.3 liblua5.3-dev lcov vim \
      net-tools iproute2

RUN apt-get install -y \
        libprotobuf-c-dev \
        protobuf-c-compiler

COPY docker/ubuntu20-gtest/lcov-2.3.tar.gz /home/

    RUN cd /home && pwd && ls -al && \
        tar -zxvf lcov-2.3.tar.gz && \
        cd lcov-2.3 && \
        make install

RUN groupadd -r -g 92 frr && \
      groupadd -r -g 85 frrvty && \
      adduser --system --ingroup frr --home /home/frr \
              --gecos "FRR suite" --shell /bin/bash frr && \
      usermod -a -G frrvty frr && \
      useradd -d /var/run/exabgp/ -s /bin/false exabgp && \
      echo 'frr ALL = NOPASSWD: ALL' | tee /etc/sudoers.d/frr && \
      mkdir -p /home/frr && chown frr.frr /home/frr

#for libyang 2
RUN apt-get install -y cmake libpcre2-dev

COPY tests/topotests/docker/buster_dep /home
RUN cd /home && \
    dpkg -i *.deb

USER frr:frr

COPY --chown=frr:frr . /home/frr/frr/

RUN cd && ls -al && ls -al frr

RUN cd ~/frr && \
    if [ ! -d "./libyang" ]; then \
      git clone https://github.com/CESNET/libyang.git && \
      cd libyang && \
      git checkout v2.0.0; \
    fi

# build and install libyang2
RUN cd ~/frr && pwd && ls -al && \
    cd ./libyang && \
    mkdir build; cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
          -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make -j $(nproc) && \
    sudo make install

RUN cd ~/frr && \
    if [ ! -d "./googletest" ]; then \
      git clone https://github.com/google/googletest.git && \
      cd googletest && \
      git checkout v1.16.x; \
    fi

# build and install gtest
RUN cd ~/frr && pwd && ls -al && \
    cd ./googletest && \
    mkdir build; cd build && \
    cmake ..  &&  make && \
    sudo make install


RUN cd ~/frr && \
    ./bootstrap.sh && \
    ./configure \
       --prefix=/usr \
       --localstatedir=/var/run/frr \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
       --enable-vtysh \
       --enable-pimd \
       --enable-sharpd \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-vty-group=frrvty \
       --enable-snmp=agentx \
       --enable-scripting \
       --enable-protobuf \
       --enable-fpm \
       --enable-zebra-unit-testing \
       --enable-gcov \
       --with-pkg-extra-version=-my-manual-build && \
    make -j $(nproc) && \
    sudo make install

RUN cd ~/frr && make check || true

COPY docker/ubuntu20-ci/docker-start /usr/sbin/docker-start
CMD ["/usr/sbin/docker-start"]
