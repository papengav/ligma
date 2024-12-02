#include "ShellManager.h"

bool ShellManager::spawnShell() {
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	// Not member variables since they won't be kept
	HANDLE hStdOutWrite, hStdInRead;
	
	// Child STDOUT pipe
	if (!CreatePipe(&m_hStdOutRead, &hStdOutWrite, &sa, 0)) {
		std::cout << "Failed to create child STDOUT Pipe" << "\n";
		return false;
	}
	// Child STDIN pipe
	if (!CreatePipe(&hStdInRead, &m_hStdInWrite, &sa, 0)) {
		std::cout << "Failed to create child STDIN Pipe" << "\n";
		CloseHandle(m_hStdOutRead);
		return false;
	}

	// Prevent STDOUT write handle inheritence
	SetHandleInformation(m_hStdOutRead, HANDLE_FLAG_INHERIT, 0);

	// Setup process to use STD pipes
	STARTUPINFO si = {};
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = hStdInRead;
	si.hStdOutput = hStdOutWrite;
	si.hStdError = hStdOutWrite;

	wchar_t cmd[] = L"cmd.exe";

	// child process, launches command prompt
	if (!CreateProcess(
		NULL,
		cmd,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&si,
		&m_pi)
		) {
		std::cout << "Failed to spawn shell process" << "\n";
		return false;
	}

	// Unused handles, we'll never write to the shell's stdOut or read from the shell's stdIn
	// However, they were necessary per Window's API to create the process
	CloseHandle(hStdOutWrite);
	CloseHandle(hStdInRead);

	// Start the user in the C:/ drive
	std::string cdCmd = "cd C:/";
	executeCommand(cdCmd);

	return true;
}

void ShellManager::cleanup() {
	if (m_hStdOutRead) {
		CloseHandle(m_hStdOutRead);
		m_hStdOutRead = nullptr;
	}
	if (m_hStdInWrite) {
		CloseHandle(m_hStdInWrite);
		m_hStdInWrite = nullptr;
	}
	if (m_pi.hProcess) CloseHandle(m_pi.hProcess);
	if (m_pi.hThread) CloseHandle(m_pi.hThread);
	m_pi = {};
}

std::string ShellManager::executeCommand(std::string& cmd) {
	// Shell won't execute unless there is a newline
	if (cmd.back() != '\n') cmd += '\n';

	// ReadFile will block until the read handle says it's done writing - which is never with a shell. So we need to
	// use a hacky method to terminate early by echoing out something that the user would hopefullY never do themself.
	std::string exitFlag = "FLG_TERM_OUT";
	std::string command = cmd + " && echo " + exitFlag + "\n";

	// Execute command
	DWORD bytesWritten;
	if (!WriteFile(m_hStdInWrite, command.c_str(), command.size(), &bytesWritten, NULL)) {
		std::cout << "Failed to execute command" << "\n";
		return "";
	}

	// Build string of shell output
	char outputbuf[1024]; // Probably overkill, but this isn't a super performant system
	DWORD bytesRead, bytesRemaining;
	std::string output;

	while (ReadFile(m_hStdOutRead, outputbuf, sizeof(outputbuf) - 1, &bytesRead, NULL) && bytesRead > 0) {
		outputbuf[bytesRead] = '\0';
		output += outputbuf;

		// If our exit flag is in the ouput, we've reached the end of the expected output
		if (output.find(exitFlag) != std::string::npos) {
			// remove from last C:/ since that's where our additional echo will be and we don't want to send back the terminal header
			output.erase(output.find_last_of("C:/") - 2);
			break;
		}
	}

	return output;
}