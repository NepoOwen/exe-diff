#pragma once
#include "src/pe/image.hpp"
#include <string_view>
#include <vector>

namespace sig {
	struct Pattern {
		std::vector<uint8_t> bytes;
		std::vector<bool> wild;
	};

	bool parse(std::string_view text, Pattern& out);
	std::vector<uint32_t> find(const pe::Image& img, const Pattern& p, size_t limit);
}
