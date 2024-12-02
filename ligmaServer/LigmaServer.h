#undef UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <cstdio>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ShellManager.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "libssl.lib")
#pragma comment (lib, "libcrypto.lib")

#define DEFAULT_BUFLEN 2048
#define DEFAULT_PORT "42069"

class LigmaServer {
private:
	WSADATA wsaData;
	SOCKET listenSocket;
	SOCKET clientSocket;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen;

	SSL_CTX* sslCtx; // Server context
	SSL* ssl;		 // Client session info

	bool tryHandshake();
	int initWinsock();
	SOCKET setupListener();
	SOCKET acceptClient();
	bool processClient(ShellManager& shellManager);
	void handleError(const std::string& message, int errorCode);
	void cleanupClientSession();
	void cleanup();

	SSL_CTX* initializeSSLContext();
	void configureCerts(SSL_CTX* ctx, const std::string& certFile, const std::string& keyFile);

public:
	LigmaServer()
		: listenSocket(INVALID_SOCKET), clientSocket(INVALID_SOCKET),
		recvbuflen(DEFAULT_BUFLEN), sslCtx(nullptr), ssl(nullptr) {}

	~LigmaServer() { cleanup(); }

	bool initialize(const std::string& certFile, const std::string& keyFile);
	void start();
};
