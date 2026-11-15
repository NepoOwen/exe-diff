#pragma once
#include "src/ida/install.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace ida {
	struct Side {
		std::filesystem::path dir;
		std::string label;
	};

	// analyses (once per exe) and decompiles each side's request; returns how many sides failed
	size_t decompile(const Install& ida, const std::filesystem::path& scripts, const std::vector<Side>& sides);
}
