#pragma once
#include <cstdint>
#include <string>

namespace report {
	struct PairSide {
		std::wstring exe_path;
		uint64_t size;
		std::string md5;
		std::wstring work_dir;
	};

	bool write_pair_txt(const wchar_t* path, const PairSide& old_side, const PairSide& new_side, std::string& err);
}
