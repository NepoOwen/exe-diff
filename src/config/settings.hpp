#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace config {
	struct Settings {
		std::wstring ida_dir;
		std::vector<std::string> warnings;
	};

	enum class Load { Ok, Missing, Unreadable };

	// "key = value" lines, ';' and '#' start a comment line, [section] headers are ignored
	Settings parse(std::string_view text);
	Load load(const std::filesystem::path& file, Settings& out);
	bool write_default(const std::filesystem::path& file, const std::wstring& ida_dir);
}
