#include "src/config/settings.hpp"
#include "src/console/console.hpp"
#include "src/diff/normalize_c.hpp"
#include "src/func/discover.hpp"
#include "src/ida/exchange.hpp"
#include "src/ida/install.hpp"
#include "src/ida/step.hpp"
#include "src/match/match.hpp"
#include "src/pe/image.hpp"
#include "src/report/html.hpp"
#include "src/report/markdown.hpp"
#include "src/report/notes.hpp"
#include "src/report/pair.hpp"
#include "src/sig/scan.hpp"
#include "src/text/render.hpp"
#include "src/util/md5.hpp"
#include "src/util/wide.hpp"
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

namespace {
	constexpr const char* kNotRendered = "; not shown: the inputs are too different to pair fully";

	struct Args {
		std::wstring old_path, new_path, out, work, ida_dir;
		bool no_ida = false;
	};

	struct Summary {
		size_t old_funcs = 0, new_funcs = 0, same = 0, changed = 0, calls = 0, added = 0, removed = 0;
		bool too_different = false, no_decompiled = false;
		std::vector<std::wstring> sides;
		std::string report, agent;
	};

	struct IdaPlan {
		bool use = false;
		ida::Install install;
		std::filesystem::path scripts;
	};

	std::filesystem::path exe_dir() {
		std::wstring buf(32768, L'\0');
		DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
		buf.resize(n);
		return std::filesystem::path(buf).parent_path();
	}

	std::string shown(const std::filesystem::path& p) {
		std::error_code ec;
		auto abs = std::filesystem::absolute(p, ec);
		return util::narrow((ec ? p : abs.lexically_normal()).wstring());
	}

	bool parse(int argc, wchar_t** argv, Args& a) {
		std::vector<std::wstring> pos;
		for (int i = 1; i < argc; ++i) {
			std::wstring s = argv[i];
			if ((s == L"--out" || s == L"--work" || s == L"--ida") && i + 1 < argc) (s == L"--out" ? a.out : s == L"--work" ? a.work : a.ida_dir) = argv[++i];
			else if (s == L"--no-ida") a.no_ida = true;
			else if (s.starts_with(L"--")) return false;
			else pos.push_back(s);
		}
		if (pos.size() != 2) return false;
		a.old_path = pos[0];
		a.new_path = pos[1];
		return true;
	}

	struct Clock {
		std::chrono::steady_clock::time_point last = std::chrono::steady_clock::now();
		std::vector<report::Stage>& stages;
		void mark(const char* name) {
			auto now = std::chrono::steady_clock::now();
			double s = std::chrono::duration<double>(now - last).count();
			last = now;
			stages.push_back({ name, s });
		}
	};

	bool failed(std::string& dest, const std::string& msg) {
		dest = msg;
		return false;
	}

	report::Entry make_entry(report::Kind kind, const std::string& name) {
		report::Entry e{};
		e.kind = kind;
		e.name = name;
		e.similarity = 1.0f;
		return e;
	}

	struct Decompiled {
		const wchar_t* work;
		std::unordered_set<std::string> keep;
		size_t found = 0;
		void read(const pe::Image& img, uint32_t rva, std::vector<std::string>& c, std::string& error) {
			std::string text;
			if (!ida::read_result(work, img, rva, text, error)) return;
			++found;
			if (!text.empty()) c = diff::normalize_c(text, keep);
			else if (error.empty()) error = "decompiler failed without a message";
		}
	};

	std::string old_sig_in_new(const std::string& s, const pe::Image& ib, const func::Set& b, const std::vector<std::string>& names, int paired) {
		sig::Pattern p;
		if (s.empty() || !sig::parse(s, p)) return {};
		auto hits = sig::find(ib, p, 2);
		if (hits.empty()) return "the old signature finds nothing in the new exe";
		if (hits.size() > 1) return "the old signature finds more than one place in the new exe";
		int f = b.at(hits[0]);
		if (f >= 0 && f == paired) return "the old signature still finds this function in the new exe";
		std::string where = f >= 0 ? names[f] : "an address that starts no function";
		char va[24];
		std::snprintf(va, sizeof(va), " (0x%llX)", static_cast<unsigned long long>(ib.image_base + hits[0]));
		return "the old signature finds " + where + va + " in the new exe";
	}

	report::PairSide pair_side(const std::wstring& exe, const wchar_t* work, const pe::Image& img) {
		auto absolute = [](const std::filesystem::path& p) {
			std::error_code ec;
			auto abs = std::filesystem::absolute(p, ec);
			return (ec ? p : abs.lexically_normal()).wstring();
		};
		return { absolute(exe), img.file.size(), util::md5_hex(img.file.data(), img.file.size()), absolute(ida::side_dir(work, img)) };
	}
}

static bool compare(const Args& args, Summary& sum, std::string& err_out) {
	report::Data data{};
	data.old_path = util::narrow(args.old_path);
	data.new_path = util::narrow(args.new_path);
	Clock clock{ .stages = data.stages };

	pe::Image ia, ib;
	std::string err;
	if (!pe::load(args.old_path.c_str(), ia, err)) return failed(err_out, data.old_path + ": " + err);
	if (!pe::load(args.new_path.c_str(), ib, err)) return failed(err_out, data.new_path + ": " + err);
	if (ia.arch != ib.arch)
		return failed(err_out, std::string("old is ") + pe::arch_name(ia.arch) + " but new is " + pe::arch_name(ib.arch) + ": both files must have the same architecture");
	data.arch = pe::arch_name(ia.arch);
	clock.mark("load");

	func::Set a, b;
	func::discover(ia, a);
	func::discover(ib, b);
	auto add_notes = [&](const char* side, const std::wstring& path, const pe::Image& img, const func::Set& set) {
		auto file = util::narrow(std::filesystem::path(path).filename().wstring());
		for (auto& n : report::notes_for(side, file, img, set)) data.notes.push_back(n);
	};
	add_notes("old", args.old_path, ia, a);
	add_notes("new", args.new_path, ib, b);
	clock.mark("discover");

	match::Result r;
	match::run(a, b, r);
	match::Names names;
	match::name(ia, a, ib, b, r, names);
	clock.mark("match");

	std::vector<uint32_t> ask_old, ask_new;
	if (!r.too_different) {
		ask_old.assign(r.removed.begin(), r.removed.end());
		ask_new.assign(r.added.begin(), r.added.end());
		for (auto& p : r.pairs)
			if (p.status != match::Status::Same) { ask_old.push_back(p.old_idx); ask_new.push_back(p.new_idx); }
	}
	if (!ida::write_request(args.work.c_str(), args.old_path.c_str(), ia, a, ask_old, names.old_names, err)) return failed(err_out, err);
	if (!ida::write_request(args.work.c_str(), args.new_path.c_str(), ib, b, ask_new, names.new_names, err)) return failed(err_out, err);
	clock.mark("request");
	Decompiled dec{ args.work.c_str() };
	dec.keep.insert(names.old_names.begin(), names.old_names.end());
	dec.keep.insert(names.new_names.begin(), names.new_names.end());

	data.old_funcs = a.funcs.size();
	data.new_funcs = b.funcs.size();
	data.too_different = r.too_different;
	for (auto& p : r.pairs) {
		if (p.status == match::Status::Same) { ++data.same; continue; }
		auto e = make_entry(p.status == match::Status::Changed ? report::Kind::Changed : report::Kind::RefChanged, names.old_names[p.old_idx]);
		auto& fa = a.funcs[p.old_idx];
		auto& fb = b.funcs[p.new_idx];
		e.old_va = ia.image_base + fa.rva; e.new_va = ib.image_base + fb.rva;
		e.old_size = fa.size; e.new_size = fb.size;
		e.similarity = p.similarity;
		e.asm_old = text::render(ia, a, p.old_idx, names.old_names);
		e.asm_new = text::render(ib, b, p.new_idx, names.new_names);
		dec.read(ia, fa.rva, e.c_old, e.c_error_old);
		dec.read(ib, fb.rva, e.c_new, e.c_error_new);
		ida::read_signature(dec.work, ia, fa.rva, e.sig_old, e.sig_error_old);
		ida::read_signature(dec.work, ib, fb.rva, e.sig_new, e.sig_error_new);
		if (e.sig_old != e.sig_new) e.sig_note = old_sig_in_new(e.sig_old, ib, b, names.new_names, static_cast<int>(p.new_idx));
		data.entries.push_back(std::move(e));
	}
	for (uint32_t j : r.added) {
		auto e = make_entry(report::Kind::Added, names.new_names[j]);
		e.new_va = ib.image_base + b.funcs[j].rva;
		e.new_size = b.funcs[j].size;
		if (r.too_different) e.asm_new = { kNotRendered };
		else e.asm_new = text::render(ib, b, j, names.new_names);
		dec.read(ib, b.funcs[j].rva, e.c_new, e.c_error_new);
		ida::read_signature(dec.work, ib, b.funcs[j].rva, e.sig_new, e.sig_error_new);
		data.entries.push_back(std::move(e));
	}
	for (uint32_t i : r.removed) {
		auto e = make_entry(report::Kind::Removed, names.old_names[i]);
		e.old_va = ia.image_base + a.funcs[i].rva;
		e.old_size = a.funcs[i].size;
		if (r.too_different) e.asm_old = { kNotRendered };
		else e.asm_old = text::render(ia, a, i, names.old_names);
		dec.read(ia, a.funcs[i].rva, e.c_old, e.c_error_old);
		ida::read_signature(dec.work, ia, a.funcs[i].rva, e.sig_old, e.sig_error_old);
		e.sig_note = old_sig_in_new(e.sig_old, ib, b, names.new_names, -1);
		data.entries.push_back(std::move(e));
	}
	clock.mark("render");

	std::error_code ec;
	std::filesystem::create_directories(args.out, ec);
	if (ec) return failed(err_out, "cannot create " + util::narrow(args.out) + ": " + ec.message());
	auto out = std::filesystem::path(args.out);
	if (!report::write_map_csv((out / L"map.csv").c_str(), ia, a, ib, b, r, names, err)) return failed(err_out, err);
	if (!report::write_pair_txt((out / L"pair.txt").c_str(), pair_side(args.old_path, args.work.c_str(), ia), pair_side(args.new_path, args.work.c_str(), ib), err)) return failed(err_out, err);
	if (!report::write_html((out / L"report.html").c_str(), data, err)) return failed(err_out, err);
	if (!report::write_markdown(out.c_str(), data, err)) return failed(err_out, err);
	clock.mark("write");

	size_t changed = 0, calls = 0;
	for (auto& p : r.pairs) {
		changed += p.status == match::Status::Changed;
		calls += p.status == match::Status::RefChanged;
	}
	sum = {};
	sum.old_funcs = a.funcs.size();
	sum.new_funcs = b.funcs.size();
	sum.same = data.same;
	sum.changed = changed;
	sum.calls = calls;
	sum.added = r.added.size();
	sum.removed = r.removed.size();
	sum.too_different = r.too_different;
	sum.no_decompiled = !data.entries.empty() && !dec.found;
	sum.sides.push_back(ida::side_dir(args.work.c_str(), ia));
	if (auto sb = ida::side_dir(args.work.c_str(), ib); sb != sum.sides[0]) sum.sides.push_back(sb);
	sum.report = shown(out / L"report.html");
	sum.agent = shown(out / report::kAgentMarkdown);
	return true;
}

namespace {
	constexpr const char* kUsage =
		"usage: exediff <old.exe> <new.exe> [options]\n"
		"  --out <dir>   where the report goes (default: out next to exediff.exe)\n"
		"  --work <dir>  where the IDA files go (default: work next to exediff.exe)\n"
		"  --ida <dir>   the IDA Pro install folder, overrides ida_dir in exediff.ini\n"
		"  --no-ida      skip IDA: the report has assembly only\n";

	std::string leaf(const std::wstring& path) {
		return util::narrow(std::filesystem::path(path).filename().wstring());
	}

	bool resolve_ida(const Args& args, const config::Settings& cfg, const std::filesystem::path& home, IdaPlan& plan, std::string& err) {
		if (args.no_ida) return true;
		bool from_flag = !args.ida_dir.empty();
		const std::wstring& configured = from_flag ? args.ida_dir : cfg.ida_dir;
		std::string problem;
		if (!configured.empty()) {
			if (!ida::inspect(configured, plan.install, problem)) return failed(err, std::string(from_flag ? "--ida: " : "ida_dir in exediff.ini: ") + problem + ". Fix it, or run with --no-ida for an assembly-only report.");
		} else if (!ida::detect(plan.install)) {
			return true;
		}
		if (!ida::find_scripts(home, plan.scripts, problem)) return failed(err, problem);
		plan.use = true;
		return true;
	}
}

int wmain(int argc, wchar_t** argv) {
	console::init();
	auto started = std::chrono::steady_clock::now();
	Args args;
	if (!parse(argc, argv, args)) {
		std::fputs(kUsage, stderr);
		return 1;
	}
	auto home = exe_dir();
	if (args.out.empty()) args.out = (home / L"out").wstring();
	if (args.work.empty()) args.work = (home / L"work").wstring();

	auto fatal = [](const std::string& msg) {
		console::clear_progress();
		std::fflush(stdout);
		std::fprintf(stderr, "error: %s\n", msg.c_str());
		return 1;
	};

	std::printf("exediff: %s (old) vs %s (new)\n", leaf(args.old_path).c_str(), leaf(args.new_path).c_str());
	std::fflush(stdout);
	for (auto* path : { &args.old_path, &args.new_path }) {
		std::error_code ec;
		if (!std::filesystem::is_regular_file(*path, ec)) return fatal(util::narrow(*path) + ": file not found");
	}

	config::Settings cfg;
	auto ini = home / L"exediff.ini";
	switch (config::load(ini, cfg)) {
	case config::Load::Ok:
		for (auto& w : cfg.warnings) console::warn(w);
		break;
	case config::Load::Missing: {
		ida::Install found;
		if (config::write_default(ini, ida::detect(found) ? found.dir.wstring() : std::wstring()))
			console::info("created " + shown(ini) + ": set ida_dir there if IDA is installed somewhere unusual");
		break;
	}
	case config::Load::Unreadable:
		console::warn("cannot read " + shown(ini) + ", using the defaults");
		break;
	}

	IdaPlan plan;
	std::string err;
	if (!resolve_ida(args, cfg, home, plan, err)) return fatal(err);

	console::step(1, 3, "Comparing the two exes");
	auto t = std::chrono::steady_clock::now();
	auto since = [&] { return std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count(); };
	Summary sum;
	if (!compare(args, sum, err)) return fatal(err);
	console::good("done in " + console::elapsed(since()));
	console::info(std::to_string(sum.changed) + " changed, " + std::to_string(sum.calls) + " calls changed, " + std::to_string(sum.added) + " added, " + std::to_string(sum.removed) + " removed (" + std::to_string(sum.same) + " identical)");
	if (sum.too_different) console::warn("warning: the inputs are too different to pair fully");

	console::step(2, 3, "Decompiling the changed functions with IDA");
	size_t failed_sides = 0;
	if (args.no_ida) {
		console::info("skipped (--no-ida): the report has assembly only");
	} else if (!plan.use) {
		console::warn("IDA Pro was not found, so the report has assembly only.");
		console::warn("Install IDA Pro 9 with the Hex-Rays decompiler, or set ida_dir in " + shown(ini) + " (or pass --ida <folder>).");
	} else {
		console::info("using " + shown(plan.install.dir));
		std::vector<ida::Side> sides;
		for (size_t k = 0; k < sum.sides.size(); ++k) {
			std::string label = sum.sides.size() == 1 ? "both exes (" + leaf(args.old_path) + ")"
				: k == 0 ? "old exe (" + leaf(args.old_path) + ")" : "new exe (" + leaf(args.new_path) + ")";
			sides.push_back({ sum.sides[k], label });
		}
		failed_sides = ida::decompile(plan.install, plan.scripts, sides);
	}

	console::step(3, 3, "Writing the report");
	t = std::chrono::steady_clock::now();
	Summary final_sum;
	if (!compare(args, final_sum, err)) return fatal(err);
	console::good("done in " + console::elapsed(since()));
	if (final_sum.no_decompiled) console::warn("no decompiled C was found, the report has assembly only");

	if (failed_sides) console::warn("IDA failed for " + std::to_string(failed_sides) + " of " + std::to_string(sum.sides.size()) + " exes: the report is incomplete, see above");
	std::printf("\nFinished in %s.\n", console::elapsed(std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count()).c_str());
	std::printf("  report     %s\n", final_sum.report.c_str());
	std::printf("  for an AI  %s  (start here, it points into report-do-not-read-in-full.md)\n", final_sum.agent.c_str());
	if (plan.use && !final_sum.sides.empty()) std::printf("  IDA files  %s  (keep: the analysis is reused next time)\n", shown(std::filesystem::path(final_sum.sides[0]).parent_path()).c_str());
	return failed_sides ? 2 : 0;
}
