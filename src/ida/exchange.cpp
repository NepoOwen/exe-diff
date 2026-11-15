#include "src/ida/exchange.hpp"
#include "src/util/wide.hpp"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace ida {
	namespace {
		std::string hex(uint32_t v) {
			char buf[16];
			std::snprintf(buf, sizeof(buf), "%X", v);
			return buf;
		}

		bool slurp(const fs::path& p, std::string& out) {
			std::ifstream f(p, std::ios::binary);
			if (!f) return false;
			std::stringstream ss;
			ss << f.rdbuf();
			out = ss.str();
			return true;
		}
	}

	std::wstring side_dir(const wchar_t* work, const pe::Image& img) {
		wchar_t buf[24];
		std::swprintf(buf, 24, L"%016llX", static_cast<unsigned long long>(img.content_hash));
		return (fs::path(work) / buf).wstring();
	}

	bool write_request(const wchar_t* work, const wchar_t* exe_path, const pe::Image& img, const func::Set& set,
		const std::vector<uint32_t>& func_idxs, const std::vector<std::string>& names, std::string& err) {
		fs::path side = side_dir(work, img);
		std::error_code ec;
		fs::create_directories(side, ec);
		if (ec) { err = "cannot create " + util::narrow(side.wstring()) + ": " + ec.message(); return false; }
		auto input = side / L"input.exe";
		if (!fs::exists(input, ec)) {
			fs::copy_file(exe_path, input, ec);
			if (ec) { err = "cannot copy " + util::narrow(exe_path) + ": " + ec.message(); return false; }
		}

		std::vector<uint32_t> named(func_idxs);
		for (uint32_t i : func_idxs) {
			auto& f = set.funcs[i];
			for (uint32_t k = 0; k < f.ref_count; ++k) {
				auto& r = set.refs[f.first_ref + k];
				if (r.kind != disasm::RefKind::Code) continue;
				int t = set.find(r.target_rva);
				if (t >= 0 && static_cast<uint32_t>(t) != i) named.push_back(static_cast<uint32_t>(t));
			}
		}
		std::sort(named.begin(), named.end());
		named.erase(std::unique(named.begin(), named.end()), named.end());

		std::string text;
		for (uint32_t i : named)
			if (i < names.size()) text += "N " + hex(set.funcs[i].rva) + " " + names[i] + "\n";
		for (uint32_t i : func_idxs) {
			auto& f = set.funcs[i];
			text += "F " + hex(f.rva) + " " + hex(f.end) + "\n";
			for (uint32_t k = 0; k < f.chunk_count; ++k) {
				auto& c = set.chunks[f.first_chunk + k];
				text += "C " + hex(c.begin) + " " + hex(c.end) + "\n";
			}
		}
		auto path = side / L"request.txt";
		std::string previous;
		if (!slurp(path, previous) || previous != text) {
			fs::remove_all(side / L"out", ec);	// results of another request, e.g. this exe against another partner
			if (ec) { err = "cannot clear " + util::narrow((side / L"out").wstring()) + ": " + ec.message(); return false; }
		}
		std::ofstream out(path, std::ios::binary);
		out << text;
		out.close();
		if (!out) { err = "cannot write " + util::narrow(path.wstring()); return false; }
		return true;
	}

	bool read_result(const wchar_t* work, const pe::Image& img, uint32_t rva, std::string& text, std::string& error) {
		char name[16];
		std::snprintf(name, sizeof(name), "%08X", rva);
		fs::path base = fs::path(side_dir(work, img)) / L"out" / name;
		if (slurp(base.wstring() + L".c", text)) return true;
		return slurp(base.wstring() + L".err", error);
	}

	bool read_signature(const wchar_t* work, const pe::Image& img, uint32_t rva, std::string& sig, std::string& error) {
		char name[16];
		std::snprintf(name, sizeof(name), "%08X.sig", rva);
		std::string text;
		if (!slurp(fs::path(side_dir(work, img)) / L"out" / name, text)) return false;
		while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
		constexpr std::string_view kError = "error: ";
		if (text.starts_with(kError)) error = text.substr(kError.size());
		else sig = text;
		return true;
	}
}
