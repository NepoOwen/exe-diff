#include "tests/test.hpp"
#include <chrono>
#include <cstring>
#include <filesystem>

namespace test {
	static const char* g_current = nullptr;
	static int g_failures = 0;
	static bool g_skipped = false;

	std::vector<Case>& registry() {
		static std::vector<Case> cases;
		return cases;
	}

	void fail(const char* file, int line, const char* expr) {
		++g_failures;
		std::printf("  FAIL %s: %s:%d: %s\n", g_current, file, line, expr);
	}

	void skip() {
		g_skipped = true;
		std::printf("SKIP %s\n", g_current);
	}

	static const wchar_t* existing(const wchar_t* path) {
		std::error_code ec;
		return std::filesystem::exists(path, ec) ? path : nullptr;
	}

	const wchar_t* sample_old() { return existing(L"Trove_x64.old.exe"); }
	const wchar_t* sample_new() { return existing(L"Trove_x64.new.exe"); }
	const wchar_t* sample_x86_old() { return existing(L"Trove_x86.old.exe"); }
	const wchar_t* sample_x86_new() { return existing(L"Trove_x86.new.exe"); }

	const wchar_t* x86_file(const wchar_t* name) {
		static std::wstring path;
		path = std::wstring(L"tests/data/x86/") + name;
		return existing(path.c_str());
	}

	double now_seconds() {
		using namespace std::chrono;
		return duration<double>(steady_clock::now().time_since_epoch()).count();
	}
}

int main(int argc, char** argv) {
	const char* filter = argc > 1 ? argv[1] : nullptr;
	int passed = 0, failed = 0, skipped = 0;
	for (auto& c : test::registry()) {
		if (filter && !std::strstr(c.name, filter))
			continue;
		test::g_current = c.name;
		test::g_failures = 0;
		test::g_skipped = false;
		c.fn();
		if (test::g_failures) {
			++failed;
			std::printf("FAIL %s\n", c.name);
		} else if (test::g_skipped) {
			++skipped;
		} else {
			++passed;
		}
	}
	std::printf("%d passed, %d failed, %d skipped\n", passed, failed, skipped);
	return failed ? 1 : 0;
}
