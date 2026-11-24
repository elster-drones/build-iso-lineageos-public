#!/bin/sh
# Host prerequisites for building LineageOS from source
# (https://github.com/LineageOS/lineage_wiki/blob/main/_includes/templates/device_build_before_init.md).
set -eu
user=${LINEAGEOS_BUILD_USER:-of-lineageos}
check() {
    for tool in python3 git git-lfs repo rsync unzip zip openssl curl xxd setpriv hostname; do
        command -v "$tool" >/dev/null 2>&1 || return 1
    done
    # extract-utils reads Pixel carrier settings with protobuf.
    python3 -c 'import google.protobuf' >/dev/null 2>&1 || return 1
    id -u "$user" >/dev/null 2>&1
}
if check; then exit 0; fi
if [ "${1:-}" = --check ] || [ "$(id -u)" != 0 ]; then
    echo "LineageOS build prerequisites or the '$user' build account are missing. Run install-dependencies.sh as root." >&2
    exit 1
fi
if command -v dnf >/dev/null 2>&1; then
    dnf install -y git git-lfs repo python3 python3-protobuf rsync unzip zip openssl diffutils util-linux-core \
        hostname curl bc bison flex gperf ImageMagick lz4 lzop libxml2 libxslt pngcrush squashfs-tools \
        erofs-utils kmod xxd zlib-devel elfutils-libelf-devel openssl-devel gnutls-devel fontconfig freetype gnupg2
elif command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git git-lfs repo python3 \
        python3-protobuf python-is-python3 rsync unzip zip openssl diffutils util-linux hostname curl bc bison \
        build-essential flex gperf imagemagick lz4 lzop libxml2-utils xsltproc pngcrush squashfs-tools \
        erofs-utils kmod xxd zlib1g-dev libelf-dev libssl-dev libgnutls28-dev fontconfig gnupg
else
    echo 'Install the LineageOS build prerequisites for this host distribution.' >&2
    exit 1
fi
id -u "$user" >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$user"
check
