#include "LigmaServer.h"

int LigmaServer::initWinsock() {
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (iResult != 0) handleError("WSAStartup failed with error", iResult);

	return iResult;
}

SOCKET LigmaServer::setupListener() {
	struct addrinfo* result = nullptr, hints = {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	int iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);

	if (iResult != 0) {
		handleError("getaddrinfo failed", iResult);
		return INVALID_SOCKET;
	}

	SOCKET serverSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if (serverSocket == INVALID_SOCKET) {
		handleError("socket creation failed", WSAGetLastError());
		freeaddrinfo(result);
		return INVALID_SOCKET;
	}

	iResult = bind(serverSocket, result->ai_addr, (int)result->ai_addrlen);
	freeaddrinfo(result);

	if (iResult == SOCKET_ERROR) {
		handleError("bind failed", WSAGetLastError());
		closesocket(serverSocket);
		return INVALID_SOCKET;
	}

	iResult = listen(serverSocket, SOMAXCONN);

	if (iResult == SOCKET_ERROR) {
		handleError("listen failed", WSAGetLastError());
		closesocket(serverSocket);
		return INVALID_SOCKET;
	}

	return serverSocket;
}

SOCKET LigmaServer::acceptClient() {
	SOCKET client = accept(listenSocket, NULL, NULL);

	if (client == INVALID_SOCKET) {
		handleError("accept failed", WSAGetLastError());
	}

	return client;
}

bool LigmaServer::processClient(ShellManager& shellManager) {
	int result = SSL_read(ssl, recvbuf, recvbuflen);

	if (result > 0) {
		recvbuf[result] = '\0';
		std::string command(recvbuf);
		std::cout << "Command received: " << command << "\n"; // TODO: logger

		std::string output = shellManager.executeCommand(command);

		int sendResult = SSL_write(ssl, output.c_str(), (int)output.length());

		if (sendResult <= 0) {
			ERR_print_errors_fp(stderr);
			return false;
		}

		return true;
	}
	else if (result == 0) {
		std::cout << "Client disconnected" << "\n"; // TODO: logger
		return false;
	}
	else {
		ERR_print_errors_fp(stderr);
		return false;
	}

	return true;
}

/* TODO: Logging */
void LigmaServer::handleError(const std::string& message, int errorCode) {
	std::cout << message << ": " << errorCode << "\n";
	cleanup();
}

void LigmaServer::cleanupClientSession() {
	SSL_free(ssl);
	ssl = nullptr;
	closesocket(clientSocket);
	clientSocket = INVALID_SOCKET;
}

void LigmaServer::cleanup() {
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = nullptr;
	}
	if (sslCtx) {
		SSL_CTX_free(sslCtx);
		sslCtx = nullptr;
	}
	if (clientSocket != INVALID_SOCKET) {
		closesocket(clientSocket);
		clientSocket = INVALID_SOCKET;
	}
	if (listenSocket != INVALID_SOCKET) {
		closesocket(listenSocket);
		listenSocket = INVALID_SOCKET;
	}

	WSACleanup();
}

SSL_CTX* LigmaServer::initializeSSLContext() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	// Enforce TLS, we don't want insecure sessions
	const SSL_METHOD* method = TLS_server_method();
	SSL_CTX* ctx = SSL_CTX_new(method);

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return nullptr;
	}

	return ctx;
}

void LigmaServer::configureCerts(SSL_CTX* ctx, const std::string& certFile, const std::string& keyFile) {
	if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to load cert");
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Failed to load private key");
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stderr);
		throw std::runtime_error("Key and certificate do not match");
	}
}

bool LigmaServer::initialize(const std::string& certFile, const std::string& keyFile) {
	if (initWinsock() != 0) return 1;

	sslCtx = initializeSSLContext();
	if (!sslCtx) return false;

	configureCerts(sslCtx, certFile, keyFile);

	listenSocket = setupListener();

	return listenSocket != INVALID_SOCKET;
}

bool LigmaServer::tryHandshake() {
	ssl = SSL_new(sslCtx);
	SSL_set_fd(ssl, (int)clientSocket);

	// Free mem if handshake failed
	if (SSL_accept(ssl) <= 0) {
		cleanupClientSession();
		return false;
	}

	return true;
}

/* TODO: Session timeout */
void LigmaServer::start() {
	std::cout << "Listening on port " << DEFAULT_PORT << "\n";

	// Infinitely handle client sessions one at a time
	while (true) {
		std::cout << "Waiting for client connection..." << "\n";
		clientSocket = acceptClient();

		std::cout << "Handling connection request..." << "\n";

		if (clientSocket == INVALID_SOCKET) {
			std::cout << "Client connection failed." << "\n";
			continue;
		}

		if (!tryHandshake()) {
			std::cout << "Client handshake failed." << "\n";
			continue;
		}

		std::cout << "Client connected." << "\n";
		std::cout << "Spawning client shell process" << "\n";
		ShellManager sm;
		
		if (!sm.spawnShell()) {
			continue;
		}

		std::cout << "Spawned client shell process" << "\n";

		// Handle client session until disconnect request, then free session data and socket
		// ShellManager will auto destruct once out of scope (next loop itr)
		while (processClient(sm)) {}
		cleanupClientSession();
	}
}