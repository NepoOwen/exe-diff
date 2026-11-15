#include "tests/test.hpp"
#include "src/diff/normalize_c.hpp"

using L = std::vector<std::string>;

TEST(normalize_c_renumbers_names) {
	auto out = diff::normalize_c("  v1 = sub_140123450(dword_141000010);\n  sub_140999999(dword_141000010, off_141000020);");
	CHECK(out == L({ "  v1 = sub_1(dword_1);", "  sub_2(dword_1, off_1);" }));
}

TEST(normalize_c_equal_after_move) {
	auto a = diff::normalize_c("  if ( byte_141000400 )\n    return sub_140200000(aInvalidSession_0, &unk_141000500);\n  return loc_140200010;");
	auto b = diff::normalize_c("  if ( byte_141000B20 )\n    return sub_140200720(aInvalidSession_0, &unk_141000C20);\n  return loc_140200730;");
	CHECK(!a.empty() && a == b);
}

TEST(normalize_c_keeps_given_names) {
	auto out = diff::normalize_c("CheckLoginToken(new_140003000(sub_140001000), sub_140002000);", { "sub_140001000" });
	CHECK(out == L({ "CheckLoginToken(new_140003000(sub_140001000), sub_1);" }));
}

TEST(normalize_c_drops_header_comments) {
	auto out = diff::normalize_c("// write access to const memory has been detected  \n// positive sp value has been detected\nvoid f()  \n{\n  // keep\n}\n");
	CHECK(out == L({ "void f()", "{", "  // keep", "}" }));
}

TEST(normalize_c_drops_stack_offsets) {
	auto out = diff::normalize_c("  int v6; // [rsp+20h] [rbp-48h] BYREF\n  __int64 v8; // [rsp+30h] [rbp-58h]\n  char *v9; // rbx\n  _BYTE v10[16]; // [rsp+A0h] [rbp+8h] BYREF");
	CHECK(out == L({ "  int v6; // BYREF", "  __int64 v8;", "  char *v9; // rbx", "  _BYTE v10[16]; // BYREF" }));
}

TEST(normalize_c_string_names) {
	auto out = diff::normalize_c("  a = aAuthS_1;\n  b = aAuthS_12;\n  c = aAuthS_1;");
	CHECK(out == L({ "  a = aAuthS_1;", "  b = aAuthS_2;", "  c = aAuthS_1;" }));
}
