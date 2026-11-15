#include "src/console/console.hpp"
#include "src/util/wide.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace console {
	namespace {
		bool g_live = false, g_color = false, g_progress = false;

		int width() {
			CONSOLE_SCREEN_BUFFER_INFO csbi;
			if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) return 79;
			return std::max(40, csbi.srWindow.Right - csbi.srWindow.Left);
		}

		void emit(const char* color, const std::string& text) {
			clear_progress();
			if (g_color && color) std::printf("\x1b[%sm%s\x1b[0m\n", color, text.c_str());
			else std::printf("%s\n", text.c_str());
			std::fflush(stdout);
		}
	}

	void init() {
		HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD mode = 0;
		if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode)) return;
		g_live = true;
		SetConsoleOutputCP(CP_UTF8);
		g_color = SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 && !std::getenv("NO_COLOR");
	}

	std::string elapsed(double seconds) {
		char buf[32];
		if (seconds < 60) std::snprintf(buf, sizeof(buf), "%.1f s", seconds);
		else std::snprintf(buf, sizeof(buf), "%dm %02ds", static_cast<int>(seconds / 60), static_cast<int>(seconds) % 60);
		return buf;
	}

	void step(int n, int total, const std::string& text) {
		emit(nullptr, "");
		emit("36", "[" + std::to_string(n) + "/" + std::to_string(total) + "] " + text);
	}

	void info(const std::string& text) { emit(nullptr, "      " + text); }
	void good(const std::string& text) { emit("32", "      " + text); }
	void warn(const std::string& text) { emit("33", "      " + text); }
	void bad(const std::string& text) { emit("31", "      " + text); }

	void progress(const std::string& text) {
		if (!g_live) return;
		int w = width();
		std::string line = "        " + text;
		line.resize(w, ' ');
		std::printf("\r%s", line.c_str());
		std::fflush(stdout);
		g_progress = true;
	}

	void clear_progress() {
		if (!g_progress) return;
		std::printf("\r%*s\r", width(), "");
		g_progress = false;
	}
}
