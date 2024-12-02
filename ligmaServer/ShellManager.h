#pragma once

#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <tchar.h>

class ShellManager {
private:
	HANDLE m_hStdOutRead = nullptr;
	HANDLE m_hStdInWrite = nullptr;
	PROCESS_INFORMATION m_pi = {};

	void cleanup();

public:
	ShellManager() {};
	~ShellManager() { cleanup(); }

	bool spawnShell();
	std::string executeCommand(std::string& cmd);
};