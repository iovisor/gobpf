#!/bin/bash

# Script to test gobpf
#
# `semaphore.sh` runs the tests in a rkt container with custom build
# stage1-kvm images to test under different kernels.  stage1-kvm allows
# us to run a container inside a KVM virtual machine and thus test eBPF
# workloads, which need a modern Linux kernel and root access.

set -eux
set -o pipefail

readonly kernel_versions=("4.4.45" "4.9.6" "4.10.6")
readonly rkt_version="1.26.0"

if [[ ! -f "./rkt/rkt" ]] \
  || [[ ! "$(./rkt/rkt version | awk '/rkt Version/{print $3}')" == "${rkt_version}" ]]; then

  curl -LsS "https://github.com/coreos/rkt/releases/download/v${rkt_version}/rkt-v${rkt_version}.tar.gz" \
    -o rkt.tgz

  mkdir -p rkt
  tar -xvf rkt.tgz -C rkt --strip-components=1
fi

# Pre-fetch stage1 dependency due to rkt#2241
# https://github.com/coreos/rkt/issues/2241
sudo ./rkt/rkt image fetch --insecure-options=image "coreos.com/rkt/stage1-kvm:${rkt_version}"

for kernel_version in "${kernel_versions[@]}"; do
  kernel_api_header_dir="/lib/modules/${kernel_version}-kinvolk-v1/include"
  rm -f ./rkt-uuid
  sudo timeout --foreground --kill-after=10 5m \
    ./rkt/rkt \
    run --interactive \
    --uuid-file-save=./rkt-uuid \
    --insecure-options=image,all-run \
    --dns=8.8.8.8 \
    --stage1-name="kinvolk.io/aci/rkt/stage1-kvm:${rkt_version},kernelversion=${kernel_version}" \
    --volume=gobpf,kind=host,source="$PWD" \
    docker://schu/gobpf-ci \
    --memory=1024M \
    --mount=volume=gobpf,target=/go/src/github.com/iovisor/gobpf \
    --environment=GOPATH=/go \
    --environment=C_INCLUDE_PATH="${kernel_api_header_dir}" \
    --environment=BCC_KERNEL_MODULES_SUFFIX="source" \
    --exec=/bin/sh -- -c \
    'cd /go/src/github.com/iovisor/gobpf &&
      mount -t tmpfs tmpfs /tmp &&
      mount -t debugfs debugfs /sys/kernel/debug/ &&
      go test -tags integration -v ./...'

  test_status=$(sudo ./rkt/rkt status "$(<rkt-uuid)" | awk '/app-/{split($0,a,"=")} END{print a[2]}')
  if [[ $test_status -ne 0 ]]; then
    exit "$test_status"
  fi
done
