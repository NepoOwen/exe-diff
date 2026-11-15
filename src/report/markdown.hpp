#pragma once
#include "src/report/html.hpp"
#include <string>

namespace report {
	inline constexpr const char* kAgentMarkdown = "agent.md";
	inline constexpr const char* kFullMarkdown = "report-do-not-read-in-full.md";

	struct Markdown { std::string agent, full; };
	Markdown markdown(const Data& d);
	bool write_markdown(const wchar_t* dir, const Data& d, std::string& err);
}
