#!/bin/sh

set -eux

version=$1

case "$version" in
    "1.0.2")
        tag="OpenSSL_1_0_2u"
        sha256="82fa58e3f273c53128c6fe7e3635ec8cda1319a10ce1ad50a987c3df0deeef05"
        config="shared"
        make="build_libs"
        ;;
    "1.1.0")
        tag="OpenSSL_1_1_0l"
        sha256="e2acf0cf58d9bff2b42f2dc0aee79340c8ffe2c5e45d3ca4533dd5d4f5775b1d"
        config="shared"
        make="build_libs"
        ;;
    "1.1.1")
        tag="OpenSSL_1_1_1m"
        sha256="36ae24ad7cf0a824d0b76ac08861262e47ec541e5d0f20e6d94bab90b2dab360"
        config="shared"
        make="build_libs"
        ;;
    "3.0.1")
        tag="openssl-3.0.1";
        sha256="2a9dcf05531e8be96c296259e817edc41619017a4bf3e229b4618a70103251d5"
        config="shared enable-fips"
        make="install_fips"
        ;;
    *)
        echo >&2 "error: unsupported OpenSSL version '$version'"
        exit 1 ;;
esac

cd /usr/local/src
wget -O "$tag.tar.gz" "https://github.com/openssl/openssl/archive/refs/tags/$tag.tar.gz"
echo "$sha256 $tag.tar.gz" | sha256sum -c -
rm -rf "openssl-$tag"
tar -xzf "$tag.tar.gz"

rm -rf "openssl-$version"
mv "openssl-$tag" "openssl-$version"

cd "openssl-$version"
./config $config
make -j$(nproc) $make

cp -H ./libcrypto.so "/usr/lib/libcrypto.so.${version}"
