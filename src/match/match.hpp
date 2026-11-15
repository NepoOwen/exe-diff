#pragma once
#include "src/func/discover.hpp"
#include "src/pe/image.hpp"
#include <string>
#include <vector>

namespace match {
	enum class Status : uint8_t { Same, Changed, RefChanged };
	enum class Method : uint8_t { Unique, Group, Refined, Propagated, Similar };
	struct Pair { uint32_t old_idx, new_idx; Status status; float similarity; Method method = Method::Unique; };
	struct Result {
		std::vector<Pair> pairs;
		std::vector<uint32_t> removed;
		std::vector<uint32_t> added;
		bool too_different = false;
	};

	void run(const func::Set& a, const func::Set& b, Result& out);
	float similarity(const func::Set& a, const func::Function& fa, const func::Set& b, const func::Function& fb);

	struct Names { std::vector<std::string> old_names, new_names; };
	void name(const pe::Image& ia, const func::Set& a, const pe::Image& ib, const func::Set& b, const Result& r, Names& out);
}
