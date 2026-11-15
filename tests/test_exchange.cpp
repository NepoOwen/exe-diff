#include "tests/test.hpp"
#include "src/ida/exchange.hpp"
#include "src/func/discover.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;
using B = std::vector<uint8_t>;

static fs::path fresh_dir(const char* name) {
	auto dir = fs::temp_directory_path() / "exediff_tests" / name;
	std::error_code ec;
	fs::remove_all(dir, ec);
	fs::create_directories(dir);
	return dir;
}

static void spit(const fs::path& p, const std::string& s) {
	fs::create_directories(p.parent_path());
	std::ofstream(p, std::ios::binary) << s;
}

static std::vector<std::string> lines_of(const fs::path& p) {
	std::ifstream f(p);
	std::vector<std::string> v;
	for (std::string l; std::getline(f, l);) v.push_back(l);
	return v;
}

TEST(side_dir_is_keyed_by_content) {
	pe::Image a, b, c;
	a.content_hash = 0x0123456789ABCDEFull;
	b.content_hash = 0x1111111111111111ull;
	c.content_hash = a.content_hash;
	CHECK(ida::side_dir(L"work", a) == L"work\\0123456789ABCDEF");
	CHECK(ida::side_dir(L"work", a) != ida::side_dir(L"work", b));
	CHECK(ida::side_dir(L"work", a) == ida::side_dir(L"work", c));
}

TEST(request_roundtrip) {
	auto work = fresh_dir("request");
	B code(0x80, 0xCC);
	code[0x00] = 0xE8; code[0x01] = 0x1B; code[0x02] = 0; code[0x03] = 0; code[0x04] = 0;	// call 0x1020
	code[0x05] = 0xC3;
	code[0x20] = 0xC3;
	code[0x40] = 0x90; code[0x41] = 0xC3;
	code[0x60] = 0x90; code[0x61] = 0xC3;
	auto img = test::image_from_code(code);
	img.content_hash = 0xABCDull;
	uint8_t chained_unwind[16] = { 0x21, 0, 0, 0, 0x40, 0x10, 0, 0, 0x42, 0x10, 0, 0, 0x00, 0x00, 0x02, 0x00 };
	test::put(img, 0x20100, chained_unwind, sizeof(chained_unwind));
	img.pdata = { { 0x1000, 0x1006, 0x20000 }, { 0x1040, 0x1042, 0x20000 }, { 0x1060, 0x1062, 0x20100 } };
	func::Set set;
	func::discover(img, set);
	CHECK(set.funcs.size() == 3);
	if (set.funcs.size() != 3) return;
	auto exe = work / "source.exe";
	spit(exe, std::string(1234, 'x'));
	std::vector<std::string> names = { "sub_140001000", "sub_140001020", "sub_140001040" };
	std::string err;
	CHECK(ida::write_request(work.c_str(), exe.c_str(), img, set, { 0, 2 }, names, err));
	fs::path side = ida::side_dir(work.c_str(), img);
	CHECK(fs::file_size(side / "input.exe") == 1234);
	auto req = lines_of(side / "request.txt");
	size_t f = 0, n = 0;
	for (auto& l : req) { f += l[0] == 'F'; n += l[0] == 'N'; }
	CHECK(f == 2);
	CHECK(n == 3);
	auto at = std::find(req.begin(), req.end(), "F 1040 1042");
	CHECK(at != req.end() && at + 1 != req.end() && at[1] == "C 1060 1062");
	CHECK(std::find(req.begin(), req.end(), "F 1000 1006") != req.end());
	CHECK(std::find(req.begin(), req.end(), "N 1020 sub_140001020") != req.end());
	CHECK(std::count_if(req.begin(), req.end(), [](auto& l) { return l[0] == 'C'; }) == 1);
}

TEST(read_result_cases) {
	auto work = fresh_dir("result");
	pe::Image img;
	img.content_hash = 0x42;
	fs::path out = fs::path(ida::side_dir(work.c_str(), img)) / "out";
	spit(out / "00001000.c", "int f()\n{\n}\n");
	spit(out / "00002000.err", "call analysis failed at 140002010");
	std::string text, error;
	CHECK(ida::read_result(work.c_str(), img, 0x1000, text, error));
	CHECK(text == "int f()\n{\n}\n" && error.empty());
	text.clear();
	CHECK(ida::read_result(work.c_str(), img, 0x2000, text, error));
	CHECK(text.empty() && error == "call analysis failed at 140002010");
	error.clear();
	CHECK(!ida::read_result(work.c_str(), img, 0x3000, text, error));
}

TEST(read_result_ignores_other_exe) {
	auto work = fresh_dir("other");
	pe::Image a, b;
	a.content_hash = 1;
	b.content_hash = 2;
	spit(fs::path(ida::side_dir(work.c_str(), a)) / "out" / "00001000.c", "int f();");
	std::string text, error;
	CHECK(!ida::read_result(work.c_str(), b, 0x1000, text, error));
}

TEST(request_change_drops_old_results) {
	auto work = fresh_dir("stale");
	auto img = test::image_from_code(B{ 0xC3, 0xCC, 0xCC, 0xCC, 0xC3 });
	img.content_hash = 0x77;
	img.pdata = { { 0x1000, 0x1001, 0x20000 }, { 0x1004, 0x1005, 0x20000 } };
	func::Set set;
	func::discover(img, set);
	auto exe = work / "source.exe";
	spit(exe, "x");
	std::vector<std::string> names = { "sub_140001000", "sub_140001004" };
	std::string err, text, error;
	CHECK(ida::write_request(work.c_str(), exe.c_str(), img, set, { 0 }, names, err));
	fs::path out = fs::path(ida::side_dir(work.c_str(), img)) / "out";
	spit(out / "00001000.c", "int f();");
	CHECK(ida::write_request(work.c_str(), exe.c_str(), img, set, { 0 }, names, err));
	CHECK(ida::read_result(work.c_str(), img, 0x1000, text, error));
	CHECK(ida::write_request(work.c_str(), exe.c_str(), img, set, { 1 }, names, err));
	CHECK(!ida::read_result(work.c_str(), img, 0x1000, text, error));
}

TEST(read_signature_cases) {
	auto work = fresh_dir("signature");
	pe::Image img;
	img.content_hash = 0x43;
	fs::path out = fs::path(ida::side_dir(work.c_str(), img)) / "out";
	spit(out / "00001000.sig", "48 8B 05 ? ? ? ? C3");
	spit(out / "00002000.sig", "error: Signature not unique after 1000 bytes");
	std::string sig, error;
	CHECK(ida::read_signature(work.c_str(), img, 0x1000, sig, error));
	CHECK(sig == "48 8B 05 ? ? ? ? C3" && error.empty());
	sig.clear();
	CHECK(ida::read_signature(work.c_str(), img, 0x2000, sig, error));
	CHECK(sig.empty() && error == "Signature not unique after 1000 bytes");
	error.clear();
	CHECK(!ida::read_signature(work.c_str(), img, 0x3000, sig, error));
}
