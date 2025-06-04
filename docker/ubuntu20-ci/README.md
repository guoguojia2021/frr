# Ubuntu 20.04

This builds an ubuntu 20.04 container for dev / test

# Build

```
docker build -t frr-ubuntu20:latest  -f docker/ubuntu20-ci/Dockerfile .
```
## With http proxy

```
docker build  \
  --build-arg HTTP_PROXY=$http_proxy \
  --build-arg HTTPS_PROXY=$https_proxy \
  -t frr-ubuntu20:latest  -f docker/ubuntu20-ci/Dockerfile .
```
# Running

```
docker run -d --privileged --name frr-ubuntu20 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu20:latest
```

## With tests dir mount
```
docker run -d \
  --privileged \
  --name frr-ubuntu20 \
  -v /lib/modules:/lib/modules \
  -v $(pwd)/tests/topotests:/home/frr/frr/tests/topotests \
  frr-ubuntu20:latest
```

# make check

```
docker exec frr-ubuntu20 bash -c 'cd ~/frr ; make check'
```

# interactive bash

```
docker exec -it frr-ubuntu20 bash
```

# topotest -- when Host O/S is Ubuntu only

```
docker exec frr-ubuntu20 bash -c 'cd ~/frr/tests/topotests/ospf-topo1 ; sudo pytest test_ospf_topo1.py'
```

# stop & remove container

```
docker stop frr-ubuntu20 ; docker rm frr-ubuntu18
```

# remove image

```
docker rmi frr-ubuntu20:latest
```
