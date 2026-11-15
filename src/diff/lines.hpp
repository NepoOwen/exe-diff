#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace diff {
	enum class Op : uint8_t { Keep, Del, Add };
	struct Line { Op op; uint32_t a, b; };	// a: old index (Keep, Del), b: new index (Keep, Add)
	std::vector<Line> lines(const std::vector<std::string>& a, const std::vector<std::string>& b);

	struct Hunk { uint32_t first, count; };	// slice of the Line vector
	std::vector<Hunk> hunks(const std::vector<Line>& lines, uint32_t context = 3);
}
