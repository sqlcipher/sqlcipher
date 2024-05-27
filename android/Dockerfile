# Can also be armv7a/x86_x64/i686
ARG ARCH=aarch64
ARG OPENSSL_ONLY_BUILDER_IMAGE=openssl-only-${ARCH}

ARG NDK_DIRECTORY="android-ndk-r23b"
ARG NDK_VERSION=${NDK_DIRECTORY}-linux

FROM alpine:latest as ndk-downloader
ARG NDK_VERSION
RUN apk update && apk add curl
RUN mkdir -p /opt
WORKDIR /opt
RUN curl https://dl.google.com/android/repository/${NDK_VERSION}.zip -o ${NDK_VERSION}.zip && unzip -d /opt/ndk ${NDK_VERSION}.zip && rm ${NDK_VERSION}.zip


FROM gcr.io/cloud-builders/javac:8 as openssl-builder
ARG NDK_DIRECTORY
COPY --from=ndk-downloader --link /opt/ndk/${NDK_DIRECTORY} /ndk
# gcr.io/cloud-builders/javac:8 comes with rogue python that fucks up everything.
# It should be deleted in order for everything else to work
RUN rm -rf /usr/local/bin/python
RUN apt update && apt install -y \
    git \
    cmake \
    curl \
    ninja-build \
    python3 \
    python3-pip

RUN /usr/bin/python3 -m pip install meson

RUN git clone --depth=1 https://android.googlesource.com/platform/tools/ndkports /ndkports
WORKDIR /ndkports

RUN ./gradlew --no-daemon --gradle-user-home=.gradle_home --stacktrace -PndkPath=/ndk openssl:buildPort

FROM ubuntu:latest as builder
ARG NDK_DIRECTORY
RUN apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y  \
    make \
    tclsh \
    gcc

COPY --from=ndk-downloader --link /opt/ndk/${NDK_DIRECTORY} /ndk

FROM alpine:latest as openssl-only-aarch64
COPY --from=openssl-builder /ndkports/openssl/build/port/install/Arm64 /openssl

FROM alpine:latest as openssl-only-armv7a
COPY --from=openssl-builder /ndkports/openssl/build/port/install/Arm /openssl

FROM alpine:latest as openssl-only-x86_x64
COPY --from=openssl-builder /ndkports/openssl/build/port/install/x86_x64 /openssl

FROM alpine:latest as openssl-only-i686
COPY --from=openssl-builder /ndkports/openssl/build/port/install/x86 /openssl

FROM $OPENSSL_ONLY_BUILDER_IMAGE as openssl-only

FROM builder
ARG ARCH
COPY --from=openssl-only --link /openssl /openssl
# Can be any target your ndk supports
ARG ANDROID_API=24
WORKDIR /src
VOLUME ["/src"]
ENV NDK=/ndk
ENV TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
ENV TARGET=${ARCH}-linux-android
ENV API=${ANDROID_API}
ENV CC=$TOOLCHAIN/bin/${TARGET}${API}-clang
ENV AS=$CC
ENV CXX=$TOOLCHAIN/bin/${TARGET}${API}-clang++cd
ENV LD=$TOOLCHAIN/bin/ld
ENV RANLIB=$TOOLCHAIN/bin/llvm-ranlib
ENV STRIP=$TOOLCHAIN/bin/llvm-strip

ARG USER
ARG UID
RUN useradd -ms /bin/bash -U -u $UID $USER
RUN usermod -aG sudo $USER && echo "$USER     ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers


ENTRYPOINT [ "/bin/bash", "-c", "make clean ; ./configure --host=$TARGET --enable-tempstore=yes CFLAGS='-DSQLITE_HAS_CODEC -I/openssl/include/' LDFLAGS='-L/openssl/lib -lcrypto -llog' && make clean && make -j" ]
