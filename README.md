# LIGMA - Lightweight Interactive General-purpose Management Access
The SSH clone you didn't ask for and probably will never use.

ligmaServer - the daemon/server. Run this on the machine you want to remotely control. Uses port 42069.

ligma - local machine executable (usage: ligma serverAddr port)

## Dependencies
To run as a dev, Ligma requires openssl lib (NOT LIGHT) and Windows SDK.

Win64 OpenSSL v3.4.0: https://slproweb.com/products/Win32OpenSSL.html
 
Windows SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

## Linking OpenSSL (assuming you're using VisualStudio)
Make ligma and ligmaServer separate projects under one solution.

For each project:
1) project properties->general->Additional Include Directories, path to openssl\include folder and openssl\lib\VC\x64\MT folder
2) project properties->Linker->Input->Additional Dependencies, path to openssl\lib\VC\x64\MT\libssl.lib and openssl\lib\VC\x64\MT\libcrypto.lib
3) In the solution explorer source files, add existing item and find openssl\include\openssl\applink.c

Ironically enough, openssl uses "unsafe" c functions. You may need to disable secure compiler warnings:
https://stackoverflow.com/questions/16883037/remove-secure-warnings-crt-secure-no-warnings-from-projects-by-default-in-vis

## Key and CRT
Ligma requires a crt and a private key to run the server/daemon. You can generate them yourself.
1) openssl genrsa -out server.key 2048
2) openssl req -new -key server.key -out server.csr
3) openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
4) Replace the file-paths in ligmaServer/main.cpp

## Fun facts for nerds
If you're not a nerd- why have you even read this far?

1) Uses Winsock2 for TCP socket connections.
2) Uses OpenSSL TLS for secure, encrypted data in transit.
3) The actual remote shell is a super janky child process. Don't look at the out-stream. It's a scary place.
