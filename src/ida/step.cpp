#include "src/ida/step.hpp"
#include "src/console/console.hpp"
#include "src/ida/process.hpp"
#include "src/util/wide.hpp"
#include <cstdio>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace ida {
	namespace {
		constexpr const char* kMode = "full"; // docs\ida_notes.md

		std::string text_of(const fs::path& file) {
			std::ifstream f(file, std::ios::binary);
			std::ostringstream s;
			s << f.rdbuf();
			return s.str();
		}

		std::vector<std::string> tail(const fs::path& file, size_t n) {
			std::vector<std::string> lines;
			std::istringstream in(text_of(file));
			for (std::string l; std::getline(in, l);) {
				while (!l.empty() && (l.back() == '\r' || l.back() == ' ')) l.pop_back();
				if (l.empty()) continue;
				lines.push_back(l);
				if (lines.size() > n) lines.erase(lines.begin());
			}
			return lines;
		}

		size_t count_requested(const fs::path& request) {
			std::istringstream in(text_of(request));
			size_t n = 0;
			for (std::string l; std::getline(in, l);) n += l.starts_with("F ");
			return n;
		}

		std::string status_of(const fs::path& progress) {
			unsigned pass = 0;
			size_t done = 0, total = 0;
			if (std::sscanf(text_of(progress).c_str(), "%u %zu %zu", &pass, &done, &total) != 3) return "starting IDA";
			return std::string(pass == 1 ? "preparing " : "decompiling ") + std::to_string(done) + " of " + std::to_string(total);
		}

		std::wstring script_arg(const fs::path& script, const std::wstring& rest) {
			return L"-S\"\\\"" + script.wstring() + L"\\\"" + rest + L"\"";
		}

		void explain(const ProcessResult& r, const fs::path& side, const char* what) {
			if (!r.launched) {
				console::bad("  " + r.error);
				return;
			}
			console::bad("  " + std::string(what) + " failed after " + console::elapsed(r.seconds) + " (exit code " + std::to_string(r.code) + "), see " + util::narrow((side / L"ida.log").wstring()));
			auto lines = tail(side / L"ida.log", 3);
			if (lines.empty()) lines = tail(side / L"idat.err.txt", 3);
			if (lines.empty()) lines = tail(side / L"idat.out.txt", 3);
			for (auto& l : lines) console::bad("    " + l);
		}

		ProcessResult run(const Install& ida, const fs::path& side, const std::wstring& args, const std::string& what, const std::function<std::string()>& status) {
			return run_idat(ida.idat, args, side / L"idat.out.txt", side / L"idat.err.txt", [&](double s) {
				std::string line = what;
				if (std::string st = status(); !st.empty()) line += (line.empty() ? "" : ", ") + st;
				console::progress(line + " ... " + console::elapsed(s));
			});
		}

		bool analyse(const Install& ida, const fs::path& scripts, const fs::path& side, const fs::path& db) {
			console::info("  first IDA analysis of this exe: only needed once, usually 1 to 3 minutes");
			std::wstring args = L"-A -c -L\"" + (side / L"ida.log").wstring() + L"\" " + script_arg(scripts / L"analyse.py", L"") + L" \"" + (side / L"input.exe").wstring() + L"\"";
			auto r = run(ida, side, args, "analysing", [] { return std::string(); });
			console::clear_progress();
			std::error_code ec;
			if (!r.launched || !fs::exists(db, ec)) {
				explain(r, side, "analysis");
				return false;
			}
			console::good("  analysed in " + console::elapsed(r.seconds) + ", saved for next time");
			return true;
		}

		bool decompile_side(const Install& ida, const fs::path& scripts, const fs::path& side, const fs::path& db) {
			fs::path out = side / L"out";
			std::error_code ec;
			fs::remove_all(out, ec);
			fs::path progress = out / L"progress.txt";
			std::wstring rest = L" \\\"" + (side / L"request.txt").wstring() + L"\\\" \\\"" + out.wstring() + L"\\\" " + util::widen(kMode);
			std::wstring args = L"-A -L\"" + (side / L"ida.log").wstring() + L"\" " + script_arg(scripts / L"decompile.py", rest) + L" \"" + db.wstring() + L"\"";
			auto r = run(ida, side, args, "", [&] { return status_of(progress); });
			console::clear_progress();

			auto log = tail(out / L"decompile.log", 1);
			size_t total = 0, retried = 0, failed = 0, unsigned_count = 0;
			if (!log.empty() && std::sscanf(log[0].c_str(), "%zu functions, %zu retried, %zu failed, %zu without signature", &total, &retried, &failed, &unsigned_count) == 4) {
				console::good("  decompiled in " + console::elapsed(r.seconds) + ": " + std::to_string(failed) + " failed, " + std::to_string(unsigned_count) + " without a signature");
				if (text_of(out / L"decompile.log").find("hex-rays not available") != std::string::npos)
					console::warn("  IDA has no Hex-Rays decompiler (not installed or no licence): no C for this exe, only assembly and signatures");
				return true;
			}
			explain(r, side, "decompiling");
			if (r.launched && !log.empty()) console::bad("  " + log[0]);
			return false;
		}
	}

	size_t decompile(const Install& ida, const fs::path& scripts, const std::vector<Side>& sides) {
		if (!ida.hexrays) console::warn("hexx64.dll (Hex-Rays decompiler) not found in " + util::narrow(ida.dir.wstring()) + ": expect no C diffs");
		size_t failed_sides = 0;
		for (auto& side : sides) {
			std::error_code ec;
			size_t count = count_requested(side.dir / L"request.txt");
			if (!fs::exists(side.dir / L"request.txt", ec)) {
				console::bad(side.label + ": request.txt is missing in " + util::narrow(side.dir.wstring()));
				++failed_sides;
				continue;
			}
			if (count == 0) {
				console::info(side.label + ": nothing to decompile");
				continue;
			}
			console::info(side.label + ": " + std::to_string(count) + " functions");
			fs::path db = side.dir / L"input.exe.i64";
			if (!fs::exists(db, ec) && !analyse(ida, scripts, side.dir, db)) {
				++failed_sides;
				continue;
			}
			if (!decompile_side(ida, scripts, side.dir, db)) ++failed_sides;
		}
		return failed_sides;
	}
}
