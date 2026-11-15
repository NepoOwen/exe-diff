#include <windows.h>
#define NI __declspec(noinline)
#define EXPORT __declspec(dllexport)

static volatile int g_sink;

NI int extra_first(int x) { g_sink = x - 1000; return g_sink * 13; }

NI int op_add(int x) { return x + 3; }
NI int op_sub(int x) { return x - 7; }
NI int op_mul(int x) { return x * 11; }
NI int op_xor(int x) { return x ^ 0x5a5a; }

typedef int (*op_fn)(int);
static op_fn g_ops[] = { op_add, op_sub, op_mul, op_xor };

NI int dispatch(int i, int x) { return g_ops[i & 3](x); }

#define FN(n, a, b) NI int fn_##n(int x) { g_sink = x; return (x * (a)) + (b) + g_sink; }
FN(01, 3, 17) FN(02, 5, 23) FN(03, 7, 29) FN(04, 9, 31) FN(05, 14, 38)
FN(06, 15, 41) FN(07, 17, 43) FN(08, 19, 47) FN(09, 21, 53) FN(10, 23, 59)
FN(11, 25, 61) FN(12, 27, 67) FN(13, 29, 71) FN(14, 31, 73) FN(15, 33, 79)

NI int same_a(int x) { g_sink = x + 41; return g_sink * 6 + 2; }
NI int same_b(int x) { g_sink = x + 41; return g_sink * 6 + 2; }

NI int sw_a(int k) {
	switch (k) {
	case 0: return op_add(k) + 1;
	case 1: return op_sub(k) + 2;
	case 2: return op_mul(k) + 3;
	case 3: return op_xor(k) + 4;
	case 4: return fn_01(k) + 5;
	case 5: return fn_02(k) + 6;
	case 6: return fn_03(k) + 7;
	case 7: return fn_04(k) + 8;
	case 8: return fn_05(k) + 9;
	default: return -1;
	}
}

NI int sw_b(int k) {
	switch (k) {
	case 10: return fn_06(k);
	case 11: return fn_07(k) * 2;
	case 12: return fn_08(k) * 3;
	case 13: return fn_09(k) * 4;
	case 14: return fn_10(k) * 5;
	case 15: return fn_11(k) * 6;
	case 16: return fn_12(k) * 7;
	case 17: return fn_13(k) * 8;
	default: return 0;
	}
}

NI int recurse(int n) { return n <= 1 ? 1 : n * recurse(n - 1); }

NI int show(const char* text) { return MessageBoxA(0, text, "exediff sample", 0); }
NI int tick(void) { return (int)GetTickCount() + fn_14(1); }
NI int added_fn(int x) { g_sink = x * 77; return g_sink + 54321; }

EXPORT NI int exported_fn(int x) { return fn_15(x) + same_a(x); }

NI int run(void) {
	int s = 0, i;
	for (i = 0; i < 20; ++i) s += sw_a(i) + sw_b(i) + dispatch(i, s);
	s += recurse(6) + same_b(s) + added_fn(s) + extra_first(s) + exported_fn(s);
	if (s == 0x12345) show("hello new");
	return s + tick();
}

#ifdef BUILD_DLL
BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) { (void)h; (void)why; (void)r; return run() != 0x7fffffff; }
#else
void start(void) { ExitProcess((UINT)run()); }
#endif
