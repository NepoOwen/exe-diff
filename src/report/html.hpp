#pragma once
#include "src/func/discover.hpp"
#include "src/match/match.hpp"
#include "src/pe/image.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace report {
	enum class Kind : uint8_t { Changed, RefChanged, Added, Removed };

	struct Entry {
		Kind kind;
		std::string name;
		uint64_t old_va, new_va;	// 0 when absent
		uint32_t old_size, new_size;
		float similarity;
		std::vector<std::string> asm_old, asm_new;
		std::vector<std::string> c_old, c_new;	// empty when not decompiled
		std::string c_error_old, c_error_new;
		std::string sig_old, sig_new, sig_error_old, sig_error_new;
		std::string sig_note;
	};

	struct Stage { std::string name; double seconds; };

	struct Data {
		std::string old_path, new_path;
		size_t old_funcs, new_funcs, same;
		bool too_different;
		std::string arch;	// "x86" or "x64"; empty when not stated
		std::vector<std::string> notes;	// what this comparison could not see (see notes.hpp)
		std::vector<Entry> entries;
		std::vector<Stage> stages;
	};

	std::string escape(std::string_view s);
	std::vector<const Entry*> ordered(const Data& d);
	bool write_html(const wchar_t* path, const Data& d, std::string& err);
	bool write_map_csv(const wchar_t* path, const pe::Image& ia, const func::Set& a, const pe::Image& ib, const func::Set& b,
		const match::Result& r, const match::Names& n, std::string& err);
}
