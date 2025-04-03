# peparser

Command to compile: x86_64-w64-mingw32-g++ PEparser.cpp -o pe.exe -fpermissive -Wint-to-pointer-cast

If you don't have the necessary runtime environment, you can use a Docker image. After pulling the image, use the following command format:

docker run -it -v $host-dir:$docker-dir  ghcr.io/0xk4n3ki/peparser:multi-stage-build

Note: You must mount the directory where the binary resides so that the parser can access and analyze it inside the container.

Example:


### DOS, NT, FILE Header

<img src="/dos.png">

### Optional Header

<img src="/optional.png">

### Data Directory

<img src="/directory.png">

### Section Header

<img src="/section.png">

### DLLs and Imports

<img src="/imports.png">
