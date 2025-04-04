# stage 1
FROM ubuntu AS build

RUN dpkg --add-architecture i386
RUN apt-get update
RUN export DEBIAN_FRONTEND=noninteractive
RUN apt-get install -y --no-install-recommends build-essential mingw-w64

COPY ./peparser.cpp /opt/peparser.cpp

RUN x86_64-w64-mingw32-g++ /opt/peparser.cpp -o /opt/peparser.exe -fpermissive -Wint-to-pointer-cast -static-libgcc -static-libstdc++

# stage 2
FROM ubuntu

RUN apt-get update
RUN apt-get install -y --no-install-recommends wine && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/peparser.exe /opt/peparser.exe

ENTRYPOINT ["/usr/bin/wine", "/opt/peparser.exe"]
