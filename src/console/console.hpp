#pragma once
#include <string>

namespace console {
	void init();
	std::string elapsed(double seconds);
	void step(int n, int total, const std::string& text);
	void info(const std::string& text);
	void good(const std::string& text);
	void warn(const std::string& text);
	void bad(const std::string& text);
	// rewrites the current line, only on a live console
	void progress(const std::string& text);
	void clear_progress();
}
