#include "tests/test.hpp"
#include "external/zydis/Zydis.h"

TEST(zydis_decodes_ret) {
	ZydisDecoder d;
	ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	const uint8_t code[] = { 0xC3 };
	ZydisDecodedInstruction insn;
	ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
	CHECK(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&d, code, sizeof(code), &insn, ops)));
	CHECK(insn.mnemonic == ZYDIS_MNEMONIC_RET);
	CHECK(insn.length == 1);
}
