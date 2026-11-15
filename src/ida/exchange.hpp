#pragma once
#include "src/func/discover.hpp"
#include "src/pe/image.hpp"
#include <string>
#include <vector>

namespace ida {
	// <work>\<content_hash as 16 hex digits>
	std::wstring side_dir(const wchar_t* work, const pe::Image& img);
	// copies the exe to <side_dir>\input.exe if absent and writes <side_dir>\request.txt
	bool write_request(const wchar_t* work, const wchar_t* exe_path, const pe::Image& img, const func::Set& set,
		const std::vector<uint32_t>& func_idxs, const std::vector<std::string>& names, std::string& err);
	// reads <side_dir>\out\<rva as 8 hex digits>.c into text, or .err into error; false when neither exists
	bool read_result(const wchar_t* work, const pe::Image& img, uint32_t rva, std::string& text, std::string& error);
	bool read_signature(const wchar_t* work, const pe::Image& img, uint32_t rva, std::string& sig, std::string& error);
}
