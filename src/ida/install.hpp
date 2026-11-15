#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace ida {
	struct Install {
		std::filesystem::path dir, idat;
		bool hexrays = false;
	};

	// accepts the install folder or the path of idat.exe itself; false with the reason in problem
	bool inspect(const std::filesystem::path& given, Install& out, std::string& problem);
	// IDADIR, IDA* folders in Program Files and %LOCALAPPDATA%\Programs (newest name first), then PATH
	std::vector<std::filesystem::path> candidates();
	bool detect(Install& out);
	// <exe dir>\ida, else <exe dir>\..\ida (next to build\exediff.exe)
	bool find_scripts(const std::filesystem::path& exe_dir, std::filesystem::path& scripts, std::string& problem);
}
