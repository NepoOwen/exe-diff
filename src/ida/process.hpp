#pragma once
#include <filesystem>
#include <functional>
#include <string>

namespace ida {
	struct ProcessResult {
		bool launched = false;
		unsigned long code = 0;
		double seconds = 0;
		std::string error;
	};

	// idat dies with us (job object), stdout and stderr go to files, tick runs about every 500 ms
	ProcessResult run_idat(const std::filesystem::path& idat, const std::wstring& args, const std::filesystem::path& out_file,
		const std::filesystem::path& err_file, const std::function<void(double)>& tick);
}
