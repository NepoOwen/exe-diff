#include "src/report/html.hpp"
#include "src/diff/lines.hpp"
#include "src/util/wide.hpp"
#include <algorithm>
#include <cstdio>

namespace report {
	namespace {
		const char* kStyle = R"(
:root{--bg:#ffffff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--panel:#f6f8fa;--del:#ffebe9;--delfg:#82071e;--add:#dafbe1;--addfg:#116329;--hunk:#ddf4ff;
--b-changed:#9a6700;--b-calls:#8250df;--b-added:#1a7f37;--b-removed:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;--panel:#151b23;--del:#3c1618;--delfg:#ffa198;--add:#12261e;--addfg:#7ee787;--hunk:#121d2f;
--b-changed:#d29922;--b-calls:#ab7df8;--b-added:#3fb950;--b-removed:#f85149}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,Segoe UI,sans-serif}
h1{font-size:20px;margin:0 0 8px}
.meta{color:var(--muted);margin:2px 0}
.warn{border:1px solid var(--b-removed);color:var(--b-removed);padding:6px 10px;border-radius:6px;margin:8px 0}
.notes{margin:8px 0;opacity:.8}
.note{padding:2px 0}
.counts span{margin-right:14px}
.bar{position:sticky;top:0;background:var(--bg);padding:8px 0;display:flex;gap:8px;z-index:1}
.bar input{flex:1;max-width:420px;padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--fg)}
.bar button{padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--fg);cursor:pointer}
details{border:1px solid var(--line);border-radius:6px;margin:6px 0;background:var(--bg)}
summary{cursor:pointer;padding:6px 10px;background:var(--panel);border-radius:6px;font-family:Consolas,monospace;font-size:13px}
summary span{margin-right:12px}
.badge{display:inline-block;min-width:92px;text-align:center;border-radius:10px;padding:0 6px;color:#fff;font-family:-apple-system,Segoe UI,sans-serif;font-size:12px}
.k0{background:var(--b-changed)}.k1{background:var(--b-calls)}.k2{background:var(--b-added)}.k3{background:var(--b-removed)}
.addr,.size,.sim{color:var(--muted)}
.blk{margin:8px 10px}
.blk h3{font-size:12px;margin:4px 0;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
pre{margin:0;border:1px solid var(--line);border-radius:6px;overflow-x:auto;font:12px/1.4 Consolas,monospace}
pre span{display:block;padding:0 8px;white-space:pre}
.d{background:var(--del);color:var(--delfg)}.a{background:var(--add);color:var(--addfg)}.h{background:var(--hunk);color:var(--muted)}
.err{color:var(--b-removed);font-family:Consolas,monospace;font-size:12px}
table{border-collapse:collapse;margin:6px 0}td{padding:1px 12px 1px 0;color:var(--muted)}
)";

		const char* kScript = R"(
const q=document.getElementById('q');
const sig=t=>t.replace(/\?\?/g,'?').replace(/\s+/g,' ').replace(/( \?)+$/,'').trim();
q.addEventListener('input',()=>{const t=q.value.toLowerCase(),s=sig(t);for(const e of document.querySelectorAll('details.e'))e.hidden=t&&!e.dataset.k.includes(t)&&!(s&&e.dataset.k.includes(s));});
document.getElementById('open').onclick=()=>{for(const e of document.querySelectorAll('details.e'))if(!e.hidden)e.open=true;};
document.getElementById('close').onclick=()=>{for(const e of document.querySelectorAll('details.e'))e.open=false;};
)";

		const char* kKindText[] = { "changed", "calls changed", "added", "removed" };

		std::string fmt(const char* f, auto... v) {
			char buf[128];
			std::snprintf(buf, sizeof(buf), f, v...);
			return buf;
		}

		std::string va_text(uint64_t va) { return va ? fmt("0x%llX", static_cast<unsigned long long>(va)) : std::string(); }

		void line(std::string& o, const char* cls, const char* mark, const std::string& text) {
			o += "<span";
			if (cls) { o += " class=\""; o += cls; o += "\""; }
			o += ">";
			o += mark;
			o += escape(text);
			o += "</span>";
		}

		void diff_block(std::string& o, const char* title, const std::vector<std::string>& a, const std::vector<std::string>& b) {
			o += "<div class=\"blk\"><h3>";
			o += title;
			o += "</h3><pre>";
			if (a.empty() || b.empty()) {
				for (auto& t : a) line(o, "d", "- ", t);
				for (auto& t : b) line(o, "a", "+ ", t);
			} else {
				auto d = diff::lines(a, b);
				auto hs = diff::hunks(d);
				if (hs.empty()) line(o, "h", "  ", "no line differences (the bytes differ only where addresses are masked)");
				for (auto& h : hs) {
					uint32_t oa = static_cast<uint32_t>(a.size()), ob = static_cast<uint32_t>(b.size());
					for (uint32_t k = h.first; k < h.first + h.count; ++k) {
						if (d[k].op != diff::Op::Add) oa = std::min(oa, d[k].a);
						if (d[k].op != diff::Op::Del) ob = std::min(ob, d[k].b);
					}
					line(o, "h", "@@ ", fmt("-%u +%u @@", oa + 1, ob + 1));
					for (uint32_t k = h.first; k < h.first + h.count; ++k) {
						auto& l = d[k];
						if (l.op == diff::Op::Keep) line(o, nullptr, "  ", a[l.a]);
						else if (l.op == diff::Op::Del) line(o, "d", "- ", a[l.a]);
						else line(o, "a", "+ ", b[l.b]);
					}
				}
			}
			o += "</pre></div>";
		}

		void error_line(std::string& o, const char* side, const std::string& e) {
			if (e.empty()) return;
			o += "<div class=\"err\">decompiling the ";
			o += side;
			o += " function failed: ";
			o += escape(e);
			o += "</div>";
		}

		void signature_block(std::string& o, const Entry& e) {
			bool any = !e.sig_old.empty() || !e.sig_new.empty();
			if (!any && e.sig_error_old.empty() && e.sig_error_new.empty()) return;
			bool same = !e.sig_old.empty() && e.sig_old == e.sig_new;
			o += "<div class=\"blk\"><h3>Signature";
			if (same) o += " (unchanged)";
			else if (!e.sig_old.empty() && !e.sig_new.empty()) o += " (changed)";
			o += "</h3>";
			if (any) {
				o += "<pre>";
				if (same) line(o, nullptr, "  ", e.sig_old);
				else {
					if (!e.sig_old.empty()) line(o, "d", "- ", e.sig_old);
					if (!e.sig_new.empty()) line(o, "a", "+ ", e.sig_new);
				}
				o += "</pre>";
			}
			if (!e.sig_note.empty()) o += "<div class=\"meta\">" + escape(e.sig_note) + "</div>";
			if (!e.sig_error_old.empty()) o += "<div class=\"err\">no signature for the old function: " + escape(e.sig_error_old) + "</div>";
			if (!e.sig_error_new.empty()) o += "<div class=\"err\">no signature for the new function: " + escape(e.sig_error_new) + "</div>";
			o += "</div>";
		}

		void entry_html(std::string& o, const Entry& e) {
			std::string key = e.name + " " + va_text(e.old_va) + " " + va_text(e.new_va) + " | " + e.sig_old + " | " + e.sig_new;
			std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			int k = static_cast<int>(e.kind);
			o += "<details class=\"e\" data-k=\"" + escape(key) + "\"><summary>";
			o += fmt("<span class=\"badge k%d\">%s</span>", k, kKindText[k]);
			o += "<span class=\"name\">" + escape(e.name) + "</span>";
			o += "<span class=\"addr\">";
			if (e.old_va && e.new_va) o += va_text(e.old_va) + " &rarr; " + va_text(e.new_va);
			else o += va_text(e.old_va ? e.old_va : e.new_va);
			o += "</span><span class=\"size\">";
			if (e.kind == Kind::Added) o += fmt("%u bytes", e.new_size);
			else if (e.kind == Kind::Removed) o += fmt("%u bytes", e.old_size);
			else o += fmt("%u &rarr; %u bytes (%+d)", e.old_size, e.new_size, static_cast<int>(e.new_size) - static_cast<int>(e.old_size));
			o += "</span>";
			if (e.kind == Kind::Changed) o += fmt("<span class=\"sim\">%.0f%% similar</span>", e.similarity * 100.0);
			o += "</summary>";
			signature_block(o, e);
			if (!e.c_old.empty() || !e.c_new.empty())
				diff_block(o, "C", e.c_old, e.c_new);
			if (!e.c_error_old.empty() || !e.c_error_new.empty()) {
				o += "<div class=\"blk\">";
				error_line(o, "old", e.c_error_old);
				error_line(o, "new", e.c_error_new);
				o += "</div>";
			}
			diff_block(o, "Assembly", e.asm_old, e.asm_new);
			o += "</details>\n";
		}

		bool write_file(const wchar_t* path, const std::string& text, std::string& err) {
			FILE* f = _wfopen(path, L"wb");
			if (!f) { err = "cannot write " + util::narrow(path); return false; }
			bool ok = std::fwrite(text.data(), 1, text.size(), f) == text.size();
			ok &= std::fclose(f) == 0;
			if (!ok) err = "cannot write " + util::narrow(path);
			return ok;
		}
	}

	std::string escape(std::string_view s) {
		std::string o;
		o.reserve(s.size());
		for (char c : s) {
			switch (c) {
			case '&': o += "&amp;"; break;
			case '<': o += "&lt;"; break;
			case '>': o += "&gt;"; break;
			case '"': o += "&quot;"; break;
			case '\'': o += "&#39;"; break;
			default: o += c;
			}
		}
		return o;
	}

	std::vector<const Entry*> ordered(const Data& d) {
		std::vector<const Entry*> order;
		for (auto& e : d.entries) order.push_back(&e);
		auto rank = [](const Entry* e) { return e->kind == Kind::Added ? 1 : e->kind == Kind::Removed ? 2 : 0; };
		auto addr = [](const Entry* e) { return e->old_va ? e->old_va : e->new_va; };
		std::stable_sort(order.begin(), order.end(), [&](const Entry* x, const Entry* y) {
			return rank(x) != rank(y) ? rank(x) < rank(y) : addr(x) < addr(y);
		});
		return order;
	}

	bool write_html(const wchar_t* path, const Data& d, std::string& err) {
		auto order = ordered(d);
		size_t counts[4] = {};
		for (auto& e : d.entries) ++counts[static_cast<int>(e.kind)];

		std::string o;
		o += "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>exediff report</title><style>";
		o += kStyle;
		o += "</style></head><body><h1>exediff</h1>";
		o += "<div class=\"meta\">old: " + escape(d.old_path) + fmt(" (%zu functions)", d.old_funcs) + "</div>";
		o += "<div class=\"meta\">new: " + escape(d.new_path) + fmt(" (%zu functions)", d.new_funcs) + "</div>";
		if (!d.arch.empty()) o += "<div class=\"meta\">architecture: " + escape(d.arch) + "</div>";
		if (!d.notes.empty()) {
			o += "<div class=\"notes\">";
			for (auto& n : d.notes) o += "<div class=\"note\">" + escape(n) + "</div>";
			o += "</div>";
		}
		o += "<div class=\"meta counts\">";
		o += fmt("<span>same %zu</span><span>changed %zu</span><span>calls changed %zu</span><span>added %zu</span><span>removed %zu</span>", d.same, counts[0], counts[1], counts[2], counts[3]);
		o += "</div>";
		if (d.too_different)
			o += "<div class=\"warn\">The two files are too different to pair fully: more than 5,000 functions on each side had no exact match, so the similarity pass was skipped and they are listed as added and removed.</div>";
		if (!d.stages.empty()) {
			o += "<table>";
			double total = 0;
			for (auto& s : d.stages) {
				o += "<tr><td>" + escape(s.name) + fmt("</td><td>%.2f s</td></tr>", s.seconds);
				total += s.seconds;
			}
			o += fmt("<tr><td>total</td><td>%.2f s</td></tr></table>", total);
		}
		o += "<div class=\"bar\"><input id=\"q\" placeholder=\"filter by name, address or signature\"><button id=\"open\">expand all</button><button id=\"close\">collapse all</button></div>\n";
		for (auto e : order) entry_html(o, *e);
		o += "<script>";
		o += kScript;
		o += "</script></body></html>\n";
		return write_file(path, o, err);
	}

	bool write_map_csv(const wchar_t* path, const pe::Image& ia, const func::Set& a, const pe::Image& ib, const func::Set& b,
		const match::Result& r, const match::Names& n, std::string& err) {
		std::string o = "status,name,old_va,new_va,old_size,new_size,method,similarity\n";
		auto row = [&](const char* status, const std::string& name, uint64_t ova, uint64_t nva, const func::Function* fa, const func::Function* fb, const match::Pair* p) {
			static const char* const kMethod[] = { "exact-unique", "exact-group", "refined", "propagated", "similar" };
			o += status;
			o += ',' + name + ',' + va_text(ova) + ',' + va_text(nva) + ',';
			if (fa) o += std::to_string(fa->size);
			o += ',';
			if (fb) o += std::to_string(fb->size);
			o += ',';
			if (p) o += kMethod[static_cast<size_t>(p->method)];
			o += ',';
			if (p) o += std::to_string(static_cast<int>(p->similarity * 100 + 0.5f));
			o += '\n';
		};
		for (auto& p : r.pairs) {
			const char* s = p.status == match::Status::Same ? "same" : p.status == match::Status::Changed ? "changed" : "calls_changed";
			auto& fa = a.funcs[p.old_idx];
			auto& fb = b.funcs[p.new_idx];
			row(s, n.old_names[p.old_idx], ia.image_base + fa.rva, ib.image_base + fb.rva, &fa, &fb, &p);
		}
		for (uint32_t i : r.removed) row("removed", n.old_names[i], ia.image_base + a.funcs[i].rva, 0, &a.funcs[i], nullptr, nullptr);
		for (uint32_t j : r.added) row("added", n.new_names[j], 0, ib.image_base + b.funcs[j].rva, nullptr, &b.funcs[j], nullptr);
		return write_file(path, o, err);
	}
}
