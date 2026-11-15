#include "src/ida/install.hpp"
#include "src/util/wide.hpp"
#include <algorithm>
#include <cwctype>

namespace fs = std::filesystem;

namespace ida {
	namespace {
		std::wstring env(const wchar_t* name) {
			std::wstring v(32768, L'\0');
			DWORD n = GetEnvironmentVariableW(name, v.data(), static_cast<DWORD>(v.size()));
			v.resize(n < v.size() ? n : 0);
			return v;
		}

		std::wstring lower(std::wstring s) {
			std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
			return s;
		}

		bool is_file(const fs::path& p) {
			std::error_code ec;
			return fs::is_regular_file(p, ec);
		}

		void add_ida_folders(const fs::path& base, std::vector<fs::path>& out) {
			std::error_code ec;
			std::vector<fs::path> found;
			for (fs::directory_iterator it(base, ec), end; !ec && it != end; it.increment(ec)) {
				std::error_code dec;
				if (it->is_directory(dec) && lower(it->path().filename().wstring()).starts_with(L"ida")) found.push_back(it->path());
			}
			std::sort(found.begin(), found.end(), [](const fs::path& a, const fs::path& b) { return lower(a.filename().wstring()) > lower(b.filename().wstring()); });
			out.insert(out.end(), found.begin(), found.end());
		}
	}

	bool inspect(const fs::path& given, Install& out, std::string& problem) {
		if (given.empty()) {
			problem = "the IDA folder is empty";
			return false;
		}
		fs::path dir = given;
		std::error_code ec;
		if (is_file(dir) && lower(dir.filename().wstring()) == L"idat.exe") dir = dir.parent_path();
		if (!fs::exists(dir, ec)) {
			problem = "the folder " + util::narrow(given.wstring()) + " does not exist";
			return false;
		}
		if (!fs::is_directory(dir, ec)) {
			problem = util::narrow(given.wstring()) + " is not a folder";
			return false;
		}
		fs::path idat = dir / L"idat.exe";
		if (!is_file(idat)) {
			problem = "idat.exe is not in " + util::narrow(dir.wstring()) + ": it must be the folder IDA Pro is installed in";
			return false;
		}
		out.dir = dir.make_preferred();
		out.idat = out.dir / L"idat.exe";
		out.hexrays = is_file(dir / L"plugins" / L"hexx64.dll") || is_file(dir / L"hexx64.dll");
		return true;
	}

	std::vector<fs::path> candidates() {
		std::vector<fs::path> out;
		if (auto d = env(L"IDADIR"); !d.empty()) out.emplace_back(d);
		for (const wchar_t* var : { L"ProgramW6432", L"ProgramFiles", L"ProgramFiles(x86)" })
			if (auto d = env(var); !d.empty()) add_ida_folders(d, out);
		if (auto d = env(L"LOCALAPPDATA"); !d.empty()) add_ida_folders(fs::path(d) / L"Programs", out);
		wchar_t found[MAX_PATH];
		if (SearchPathW(nullptr, L"idat.exe", nullptr, MAX_PATH, found, nullptr)) out.push_back(fs::path(found).parent_path());
		return out;
	}

	bool detect(Install& out) {
		std::string ignored;
		for (auto& c : candidates())
			if (inspect(c, out, ignored)) return true;
		return false;
	}

	bool find_scripts(const fs::path& exe_dir, fs::path& scripts, std::string& problem) {
		for (auto dir : { exe_dir / L"ida", exe_dir.parent_path() / L"ida" }) {
			if (is_file(dir / L"analyse.py") && is_file(dir / L"decompile.py")) {
				scripts = dir;
				return true;
			}
		}
		problem = "the IDA scripts (ida\\analyse.py and ida\\decompile.py) are missing: keep the ida folder next to exediff.exe";
		return false;
	}
}
