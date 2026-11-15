#include "src/report/markdown.hpp"
#include "src/diff/lines.hpp"
#include "src/util/wide.hpp"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <unordered_set>

namespace report {
	namespace {
		constexpr size_t kTopChanged = 100, kTopCalls = 30, kTopAdded = 50, kTopRemoved = 50, kTopStrings = 100, kStringMax = 160;
		const char* kKindText[] = { "changed", "calls changed", "added", "removed" };

		std::string fmt(const char* f, auto... v) {
			char buf[256];
			std::snprintf(buf, sizeof(buf), f, v...);
			return buf;
		}

		std::string va_text(uint64_t va) { return fmt("0x%llX", static_cast<unsigned long long>(va)); }

		struct Info {
			const Entry* e;
			size_t first, last;
			uint32_t plus, minus;
			bool c;
		};

		struct Changes {
			uint32_t plus = 0, minus = 0;
			std::vector<const std::string*> adds, dels;
		};

		void diff_block(std::string& o, const char* title, const std::vector<std::string>& a, const std::vector<std::string>& b, Changes& ch) {
			auto put = [&](const char* mark, const std::string& t) { o += mark; o += t; o += '\n'; };
			o += title;
			o += ":\n```diff\n";
			if (a.empty() || b.empty()) {
				for (auto& t : a) { put("- ", t); ch.dels.push_back(&t); }
				for (auto& t : b) { put("+ ", t); ch.adds.push_back(&t); }
			} else {
				auto d = diff::lines(a, b);
				auto hs = diff::hunks(d);
				if (hs.empty()) o += "  (no line differences: the bytes differ only where addresses are masked)\n";
				for (auto& h : hs) {
					uint32_t oa = static_cast<uint32_t>(a.size()), ob = static_cast<uint32_t>(b.size());
					for (uint32_t k = h.first; k < h.first + h.count; ++k) {
						if (d[k].op != diff::Op::Add) oa = std::min(oa, d[k].a);
						if (d[k].op != diff::Op::Del) ob = std::min(ob, d[k].b);
					}
					o += fmt("@@ -%u +%u @@\n", oa + 1, ob + 1);
					for (uint32_t k = h.first; k < h.first + h.count; ++k) {
						auto& l = d[k];
						if (l.op == diff::Op::Keep) put("  ", a[l.a]);
						else if (l.op == diff::Op::Del) { put("- ", a[l.a]); ch.dels.push_back(&a[l.a]); }
						else { put("+ ", b[l.b]); ch.adds.push_back(&b[l.b]); }
					}
				}
			}
			o += "```\n\n";
			ch.plus = static_cast<uint32_t>(ch.adds.size());
			ch.minus = static_cast<uint32_t>(ch.dels.size());
		}

		void literals(const std::string& s, std::vector<std::string>& out) {
			for (size_t i = 0; i < s.size(); ++i) {
				char q = s[i];
				if (q == '/' && i + 1 < s.size() && s[i + 1] == '/') return;
				if (q != '"' && q != '\'') continue;
				size_t j = i + 1;
				while (j < s.size() && s[j] != q) j += s[j] == '\\' ? 2 : 1;
				if (j >= s.size()) return;
				if (q == '"' && j > i + 1) out.push_back(s.substr(i, j - i + 1));
				i = j;
			}
		}

		void entry_md(std::string& o, const Entry& e, Changes& c, Changes& as) {
			int k = static_cast<int>(e.kind);
			o += "## ";
			o += kKindText[k];
			o += " " + e.name + "\n";
			if (e.kind == Kind::Added) o += fmt("- new %s (%u bytes)\n", va_text(e.new_va).c_str(), e.new_size);
			else if (e.kind == Kind::Removed) o += fmt("- old %s (%u bytes)\n", va_text(e.old_va).c_str(), e.old_size);
			else {
				o += fmt("- old %s (%u bytes), new %s (%u bytes, %+d)", va_text(e.old_va).c_str(), e.old_size, va_text(e.new_va).c_str(), e.new_size,
					static_cast<int>(e.new_size) - static_cast<int>(e.old_size));
				if (e.kind == Kind::Changed) o += fmt(", %.0f%% similar", e.similarity * 100.0);
				o += "\n";
			}
			if (!e.sig_old.empty() && e.sig_old == e.sig_new) o += "- signature (unchanged): `" + e.sig_old + "`\n";
			else {
				if (!e.sig_old.empty()) o += "- old signature: `" + e.sig_old + "`\n";
				if (!e.sig_new.empty()) o += "- new signature: `" + e.sig_new + "`\n";
			}
			if (!e.sig_note.empty()) o += "- " + e.sig_note + "\n";
			if (!e.sig_error_old.empty()) o += "- no signature for the old function: " + e.sig_error_old + "\n";
			if (!e.sig_error_new.empty()) o += "- no signature for the new function: " + e.sig_error_new + "\n";
			if (!e.c_error_old.empty()) o += "- decompiling the old function failed: " + e.c_error_old + "\n";
			if (!e.c_error_new.empty()) o += "- decompiling the new function failed: " + e.c_error_new + "\n";
			o += "\n";
			if (!e.c_old.empty() || !e.c_new.empty()) diff_block(o, "C", e.c_old, e.c_new, c);
			diff_block(o, "Assembly", e.asm_old, e.asm_new, as);
		}

		std::string summary_line(const Info& i) {
			auto& e = *i.e;
			std::string s = "- `" + e.name + "` ";
			if (e.kind == Kind::Added) s += fmt("%s, %u bytes", va_text(e.new_va).c_str(), e.new_size);
			else if (e.kind == Kind::Removed) s += fmt("%s, %u bytes", va_text(e.old_va).c_str(), e.old_size);
			else {
				s += fmt("%s -> %s, %u -> %u bytes", va_text(e.old_va).c_str(), va_text(e.new_va).c_str(), e.old_size, e.new_size);
				if (e.kind == Kind::Changed) s += fmt(", %.0f%% similar", e.similarity * 100.0);
				s += fmt(", %s +%u -%u", i.c ? "C" : "asm", i.plus, i.minus);
			}
			if (!e.c_error_old.empty() || !e.c_error_new.empty()) s += ", decompiling failed";
			return s + fmt(", full report lines %zu-%zu\n", i.first, i.last);
		}

		void section(std::string& o, const char* title, const char* what, std::vector<const Info*> list, size_t top, auto better) {
			if (list.empty()) return;
			std::stable_sort(list.begin(), list.end(), better);
			size_t n = std::min(top, list.size());
			o += "\n## " + std::string(title);
			o += n == list.size() ? fmt(" (all %zu %s)\n\n", n, what) : fmt(" (%zu of %zu %s)\n\n", n, list.size(), what);
			for (size_t k = 0; k < n; ++k) o += summary_line(*list[k]);
		}

		struct Found { std::string text; const Info* where; };

		void strings_section(std::string& o, const char* title, const std::vector<Found>& list) {
			if (list.empty()) return;
			size_t n = std::min(kTopStrings, list.size());
			o += "\n## " + std::string(title);
			o += n == list.size() ? fmt(" (all %zu)\n\n", n) : fmt(" (%zu of %zu, in report order)\n\n", n, list.size());
			for (size_t k = 0; k < n; ++k) {
				auto& f = list[k];
				std::string t = f.text.size() > kStringMax ? f.text.substr(0, kStringMax) + "...(cut)" : f.text;
				o += "- " + t + " in `" + f.where->e->name + "`" + fmt(", full report lines %zu-%zu\n", f.where->first, f.where->last);
			}
		}

		size_t newlines(const std::string& s, size_t from) { return static_cast<size_t>(std::count(s.begin() + from, s.end(), '\n')); }

		bool write_file(const std::filesystem::path& path, const std::string& text, std::string& err) {
			FILE* f = _wfopen(path.c_str(), L"wb");
			bool ok = f && std::fwrite(text.data(), 1, text.size(), f) == text.size();
			if (f) ok &= std::fclose(f) == 0;
			if (!ok) err = "cannot write " + util::narrow(path.wstring());
			return ok;
		}
	}

	Markdown markdown(const Data& d) {
		Markdown md;
		auto order = ordered(d);
		size_t counts[4] = {};
		for (auto& e : d.entries) ++counts[static_cast<int>(e.kind)];
		std::string counts_line = fmt("same %zu, changed %zu, calls changed %zu, added %zu, removed %zu", d.same, counts[0], counts[1], counts[2], counts[3]);

		auto& o = md.full;
		o += "# exediff full report\n\n";
		o += "Don't read this file whole. Each function is one entry that starts with a `## <kind> <name>` line. ";
		o += std::string("`") + kAgentMarkdown + "` next to this file has the summary and the line ranges of the largest entries.\n\n";
		o += "- old: " + d.old_path + fmt(" (%zu functions)\n", d.old_funcs);
		o += "- new: " + d.new_path + fmt(" (%zu functions)\n", d.new_funcs);
		if (!d.arch.empty()) o += "- architecture: " + d.arch + "\n";
		for (auto& n : d.notes) o += "- note: " + n + "\n";
		o += "- " + counts_line + "\n\n";

		std::vector<Info> infos;
		infos.reserve(order.size());
		std::vector<std::pair<std::string, size_t>> str_new, str_old;
		size_t line = newlines(o, 0);
		bool any_c = false;
		for (auto e : order) {
			size_t at = o.size();
			Changes c, as;
			entry_md(o, *e, c, as);
			bool use_c = !e->c_old.empty() && !e->c_new.empty();
			Info i{ e, line + 1, line + newlines(o, at), use_c ? c.plus : as.plus, use_c ? c.minus : as.minus, use_c };
			line = i.last;
			any_c |= !e->c_old.empty() || !e->c_new.empty() || !e->c_error_old.empty() || !e->c_error_new.empty();
			std::vector<std::string> lits;
			for (auto t : c.adds) literals(*t, lits);
			for (auto& s : lits) str_new.push_back({ std::move(s), infos.size() });
			lits.clear();
			for (auto t : c.dels) literals(*t, lits);
			for (auto& s : lits) str_old.push_back({ std::move(s), infos.size() });
			infos.push_back(i);
		}

		auto only = [&](const std::vector<std::pair<std::string, size_t>>& mine, const std::vector<std::pair<std::string, size_t>>& theirs) {
			std::unordered_set<std::string> other, seen;
			for (auto& p : theirs) other.insert(p.first);
			std::vector<Found> out;
			for (auto& p : mine)
				if (!other.count(p.first) && seen.insert(p.first).second) out.push_back({ p.first, &infos[p.second] });
			return out;
		};
		auto strings_new = only(str_new, str_old);
		auto strings_old = only(str_old, str_new);

		auto& a = md.agent;
		a += "# exediff summary\n\n";
		a += "This is the summary of what changed between two builds of an exe, small enough to read whole. ";
		a += fmt("Every detail is in `%s` next to this file (%zu lines, %.1f MB). ", kFullMarkdown, line, o.size() / 1048576.0);
		a += "Don't read that file whole: search it, or read only the line ranges given here.\n\n";
		a += "- old: " + d.old_path + fmt(" (%zu functions)\n", d.old_funcs);
		a += "- new: " + d.new_path + fmt(" (%zu functions)\n", d.new_funcs);
		if (!d.arch.empty()) a += "- architecture: " + d.arch + "\n";
		for (auto& n : d.notes) a += "- note: " + n + "\n";
		a += "- " + counts_line + "\n";
		if (d.too_different)
			a += "- warning: the two files are too different to pair fully, so many functions are listed as added and removed instead of changed\n";
		if (!d.entries.empty() && !any_c)
			a += "- no decompiled C in this report: it was made by `exediff.exe` alone; run `exediff.bat`, which also runs IDA, to get the C diffs and signatures\n";

		a += "\n## How to read the full report\n\n";
		a += "- One entry per function, starting with a line `## <kind> <name>`. The kinds are `changed` (the code changed), `calls changed` (the same code, but it calls or references different functions or data), `added` and `removed`. Search for `## changed ` to list every changed function, or search for a name, an address (`0x140...`) or a signature.\n";
		a += "- Names: `sub_<address>` is a function by its address in the old exe, and a function matched in the new exe keeps that name. `new_<address>` is a function that is only in the new exe, by its new address. Calls and references in the code use these names.\n";
		a += "- An entry lists the addresses and sizes, the old and new Signature Maker signature (IDA format, `?` is a wildcard byte) and where the old signature lands in the new exe, then a C diff (decompiled by IDA) and an assembly diff.\n";
		a += "- In the diffs, `- ` lines are the old exe, `+ ` lines the new one and `  ` lines unchanged context. `@@ -a +b @@` gives the line numbers in the old and new function.\n";
		a += "- In the lists below, `C +a -b` (or `asm` when there is no C on both sides) is the number of added and removed lines in that entry's diff.\n";

		std::vector<const Info*> by_kind[4];
		for (auto& i : infos) by_kind[static_cast<int>(i.e->kind)].push_back(&i);
		auto most_lines = [](const Info* x, const Info* y) { return x->plus + x->minus > y->plus + y->minus; };
		section(a, "Largest changes", "changed functions, most changed lines first", by_kind[0], kTopChanged, most_lines);
		section(a, "Largest calls-changed functions", "calls-changed functions, most changed lines first", by_kind[1], kTopCalls, most_lines);
		section(a, "Largest added functions", "added functions, largest first", by_kind[2], kTopAdded,
			[](const Info* x, const Info* y) { return x->e->new_size > y->e->new_size; });
		section(a, "Largest removed functions", "removed functions, largest first", by_kind[3], kTopRemoved,
			[](const Info* x, const Info* y) { return x->e->old_size > y->e->old_size; });
		strings_section(a, "Strings only in the new exe", strings_new);
		strings_section(a, "Strings only in the old exe", strings_old);
		return md;
	}

	bool write_markdown(const wchar_t* dir, const Data& d, std::string& err) {
		auto md = markdown(d);
		auto base = std::filesystem::path(dir);
		return write_file(base / kFullMarkdown, md.full, err) && write_file(base / kAgentMarkdown, md.agent, err);
	}
}
