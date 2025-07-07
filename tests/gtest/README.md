# gTest for SRv6 Functions

# Build

```shell
docker build -t frr-ubuntu20:latest  -f docker/ubuntu20-ci/Dockerfile .
```

# Run All Tests

```shell
docker run --rm -ti --name tests frr-ubuntu20:latest bash -c "cd /home/frr/frr/tests/gtest; ./gtest_zebra_srte --gtest_color=yes"
```

# Run a Specific Test Suite

```shell
docker run --rm -ti --name tests frr-ubuntu20:latest bash -c "cd /home/frr/frr/tests/gtest; ./gtest_zebra_srte --gtest_filter=PolicySetTestSuite* --gtest_color=yes"
```
