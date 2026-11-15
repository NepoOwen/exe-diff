#include "src/config/settings.hpp"
#include "src/util/wide.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>

namespace config {
	namespace {
		std::string_view trim(std::string_view s) {
			while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
			while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
			return s;
		}

		std::string_view unquote(std::string_view s) {
			if (s.size() >= 2 && s.front() == '"' && s.back() == '"') return trim(s.substr(1, s.size() - 2));
			return s;
		}
	}

	Settings parse(std::string_view text) {
		Settings s;
		if (text.starts_with("\xEF\xBB\xBF")) text.remove_prefix(3);
		for (int n = 1; !text.empty(); ++n) {
			size_t nl = text.find('\n');
			std::string_view line = trim(text.substr(0, nl));
			text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
			if (line.empty() || line[0] == ';' || line[0] == '#' || line[0] == '[') continue;
			size_t eq = line.find('=');
			if (eq == std::string_view::npos) {
				s.warnings.push_back("exediff.ini line " + std::to_string(n) + " ignored: expected key = value");
				continue;
			}
			std::string key(trim(line.substr(0, eq)));
			std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			std::string_view value = unquote(trim(line.substr(eq + 1)));
			if (key == "ida_dir") s.ida_dir = util::widen(value);
			else s.warnings.push_back("exediff.ini line " + std::to_string(n) + " ignored: unknown setting '" + key + "'");
		}
		return s;
	}

	Load load(const std::filesystem::path& file, Settings& out) {
		std::error_code ec;
		if (!std::filesystem::exists(file, ec)) return Load::Missing;
		std::ifstream f(file, std::ios::binary);
		if (!f) return Load::Unreadable;
		std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		if (f.bad()) return Load::Unreadable;
		out = parse(text);
		return Load::Ok;
	}

	bool write_default(const std::filesystem::path& file, const std::wstring& ida_dir) {
		std::ofstream f(file, std::ios::binary);
		if (!f) return false;
		f << "; exediff settings\r\n"
			 "; ida_dir: the folder IDA Pro is installed in (the one holding idat.exe).\r\n"
			 "; Leave it empty to look for IDA automatically. Without IDA the report has assembly only.\r\n"
			 "ida_dir = " << util::narrow(ida_dir) << "\r\n";
		return static_cast<bool>(f);
	}
}
