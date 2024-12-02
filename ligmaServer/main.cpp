#include "LigmaServer.h"

int main() {
	LigmaServer server;

	std::string serverCrt = "C:\\path\\to\\server\\file.crt";
	std::string serverKey = "C:\\path\\to\\server\\file.key";

	try {
		if (!server.initialize(serverCrt, serverKey)) return 1;
	}
	catch (const std::runtime_error& e) {
		std::cerr << e.what() << "\n";
		return 1;
	}

	server.start();

	return 0;
}