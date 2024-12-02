#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "libssl.lib")
#pragma comment (lib, "libcrypto.lib")

#define DEFAULT_BUFLEN 2048

class LigmaClient {
private:
	WSADATA wsaData;
	SOCKET connectSocket;
	SSL_CTX* sslCtx;
	SSL* ssl;
	std::string serverAddr;
	std::string port;

	int initWinsock();
	SOCKET createConnection();
	void handleError(const std::string& message, int errorCode);
	bool sendCommand(const std::string& sendbuf);
	bool receiveResponse();
	void cleanup();

	SSL_CTX* initializeSSLContext();

public:
	LigmaClient(const std::string& server, const std::string& port)
		: serverAddr(server), port(port), connectSocket(INVALID_SOCKET),
		  sslCtx(nullptr), ssl(nullptr) {}

	~LigmaClient() { cleanup(); }

	bool initialize();
	bool connectToServer();
	void startInteraction();
};

int LigmaClient::initWinsock() {
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	
	if (iResult != 0) handleError("WSAStartup failed with error", iResult);

	return iResult;
}

SOCKET LigmaClient::createConnection() {
	struct addrinfo* result = NULL, *ptr = NULL, hints;
	int iResult;

	// Specify IPv4 and TCP/IP
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve server addr and port
	iResult = getaddrinfo(serverAddr.c_str(), port.c_str(), &hints, &result);
	
	if (iResult != 0) {
		handleError("getaddrinfo failed with error", iResult);
		return INVALID_SOCKET;
	}

	// Create socket and attempt connections
	SOCKET ConnectSocket = INVALID_SOCKET;

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

		if (ConnectSocket == INVALID_SOCKET) {
			continue;
		}

		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);

		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}

		break; // If we made it here, we established a succesful connection
	}

	if (ConnectSocket == SOCKET_ERROR) {
		handleError("connection failed", WSAECONNREFUSED);
	}

	freeaddrinfo(result);
	return ConnectSocket;
}

/* TODO Logging */
void LigmaClient::handleError(const std::string& message, int errorCode) {
	std::cout << message << ": " << errorCode << "\n";
	WSACleanup();
}

bool LigmaClient::sendCommand(const std::string& sendbuf) {
	int iResult = SSL_write(ssl, sendbuf.c_str(), (int)sendbuf.length());
	
	if (iResult <= 0) {
		ERR_print_errors_fp(stderr);
		return false;
	}

	return true;
}

bool LigmaClient::receiveResponse() {
	char recvbuf[DEFAULT_BUFLEN];
	int iResult = SSL_read(ssl, recvbuf, DEFAULT_BUFLEN - 1);

	if (iResult > 0) {
		recvbuf[iResult] = '\0';
		std::cout << recvbuf << "\n";
	}
	else if (iResult == 0) {
		std::cout << "Connection forcbily closed by server" << "\n";
		return false;
	}
	else {
		ERR_print_errors_fp(stderr);
		return false;
	}

	return true;
}

void LigmaClient::cleanup() {
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = nullptr;
	}
	if (sslCtx) {
		SSL_CTX_free(sslCtx);
		sslCtx = nullptr;
	}

	if (connectSocket != INVALID_SOCKET) {
		closesocket(connectSocket);
		connectSocket = INVALID_SOCKET;
	}

	WSACleanup();
}

SSL_CTX* LigmaClient::initializeSSLContext() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	// Enforce TLS
	const SSL_METHOD* method = TLS_client_method();
	SSL_CTX* ctx = SSL_CTX_new(method);

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	return ctx;
}

bool LigmaClient::initialize() {
	if (initWinsock() != 0) {
		return false;
	}

	sslCtx = initializeSSLContext();

	if (!sslCtx) {
		return false;
	}

	return true;
}

bool LigmaClient::connectToServer() {
	connectSocket = createConnection();
	
	if (connectSocket == INVALID_SOCKET) {
		return false;
	}

	ssl = SSL_new(sslCtx);
	SSL_set_fd(ssl, (int)connectSocket);

	if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		return false;
	}
	
	return true;
}

void LigmaClient::startInteraction() {
	std::string cmd;

	std::cout << "Connected to " << serverAddr << " via LIGMA. Secured via TLS. Enter commands to execute or 'exit' to quit." << "\n";

	while (true) {
		std::cout << "LIGMA > ";
		std::getline(std::cin, cmd);

		if (cmd == "exit") {
			break;
		}
		if (!sendCommand(cmd)) {
			break;
		}
		if (!receiveResponse()) {
			break;
		}
	}
}

int main(int argc, char** argv) {
	if (argc != 3) {
		std::cout << "usage: " << argv[0] << "<server-addr> <port>" << "\n";
		return 1;
	}

	LigmaClient client(argv[1], argv[2]);

	if (!client.initialize()) return 1;
	if (!client.connectToServer()) return 1;

	client.startInteraction();

	return 0;
}