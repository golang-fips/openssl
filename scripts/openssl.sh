#!/bin/sh

# openssl.sh is intended for use in a CI workflow to set up various versions of OpenSSL without
# relying on availability in any particular distro's package manager. It downloads the specified
# OpenSSL version, builds it, and configures it for global use on the current machine.

set -eux

version=$1

case "$version" in
    "1.0.2")
        tag="OpenSSL_1_0_2u"
        sha256="82fa58e3f273c53128c6fe7e3635ec8cda1319a10ce1ad50a987c3df0deeef05"
        fipsmodule_version="2.0.1"
        fipsmodule_tag="OpenSSL-fips-2_0_1"
        fipsmodule_sha256="6645895f43a0229dd4b89d27874fdd91fee70d9671fff954d3da448d5fc1d331"
        config="shared fips --with-fipsdir=/usr/local/src/openssl-fips-$fipsmodule_version/dist"
        make="build_libs"
        install=""
        ;;
    "1.1.0")
        tag="OpenSSL_1_1_0l"
        sha256="e2acf0cf58d9bff2b42f2dc0aee79340c8ffe2c5e45d3ca4533dd5d4f5775b1d"
        fipsmodule_version=""
        config="shared"
        make="build_libs"
        install=""
        ;;
    "1.1.1")
        tag="OpenSSL_1_1_1m"
        sha256="36ae24ad7cf0a824d0b76ac08861262e47ec541e5d0f20e6d94bab90b2dab360"
        fipsmodule_version=""
        config="shared"
        make="build_libs"
        install=""
        ;;
    "3.0.1")
        tag="openssl-3.0.1";
        sha256="2a9dcf05531e8be96c296259e817edc41619017a4bf3e229b4618a70103251d5"
        fipsmodule_version=""
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.0.9")
        tag="openssl-3.0.9";
        sha256="2eec31f2ac0e126ff68d8107891ef534159c4fcfb095365d4cd4dc57d82616ee"
        fipsmodule_version=""
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.0.13")
        tag="openssl-3.0.13";
        sha256="e74504ed7035295ec7062b1da16c15b57ff2a03cd2064a28d8c39458cacc45fc"
        fipsmodule_version=""
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.1.5")
        tag="openssl-3.1.5";
        sha256="299ddfd0a506a6d37de56386d15ce30d344d91884dfc98ab3330b7c009029931"
        fipsmodule_version=""
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.2.1")
        tag="openssl-3.2.1";
        sha256="75cc6803ffac92625c06ea3c677fb32ef20d15a1b41ecc8dddbc6b9d6a2da84c"
        fipsmodule_version=""
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.3.0")
        tag="openssl-3.3.0";
        sha256="1a47bdc46fac256a0dc8efb696f7f76fa5f96049ba1b60fded5478bd3165c6d2"
        fipsmodule_version=""
        config="enable-fips"
        make="build_libs"
        install="install_fips"
        ;;
    "3.3.1")
        tag="openssl-3.3.1";
        sha256="133bf39b8d1635ac94a8483042cc448251b770a0d12c7af0c05ea895ddd98f1d"
        fipsmodule_version=""
        config="enable-fips"
        make="build_libs"
        install="install_fips"
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

if [ -n "$fipsmodule_version" ]; then
    wget -O "$fipsmodule_tag.tar.gz" "https://github.com/openssl/openssl/archive/refs/tags/$fipsmodule_tag.tar.gz"
    echo "$fipsmodule_sha256 $fipsmodule_tag.tar.gz" | sha256sum -c -
    rm -rf "openssl-$fipsmodule_tag"
    tar -xzf "$fipsmodule_tag.tar.gz"

    rm -rf "openssl-fips-$fipsmodule_version"
    mv "openssl-$fipsmodule_tag" "openssl-fips-$fipsmodule_version"
    (
        cd "openssl-fips-$fipsmodule_version"
        mkdir dist
        ./config -d shared fipscanisteronly --prefix=$(pwd)/dist
        make
        make install
    )
fi

cd "openssl-$version"
# -d makes a debug build which helps with debugging memory issues and
# other problems. It's not necessary for normal use.
./config -d $config

# OpenSSL 1.0.2 ./config prompts the user to run `make depend` before `make`
# when configuring in debug mode. OpenSSL 1.1.0 and above handle this
# automatically.
if [ "$version" == "1.0.2" ]; then
    make depend
fi

make -j$(nproc) $make
if [ -n "$install" ]; then
    make $install
fi

cp -H ./libcrypto.so "/usr/lib/libcrypto.so.${version}"
