/*
	Copyright (C) 2019-2021 Reiko Asakura. All Rights Reserved.

	Fruitpeel
*/

#include <libdbg.h>

#include "opcode.h"

static int decode_bl_common(
		uint16_t op_lo, uint16_t op_hi, int *imm,
		uint16_t mask_lo, uint16_t chk_lo, uint16_t mask_hi, uint16_t chk_hi)
{
	// verify the form
	if ((op_lo & mask_lo) != chk_lo) {
		SCE_DBG_LOG_ERROR("Low halfword check failed");
		return -1;
	}
	if ((op_hi & mask_hi) != chk_hi) {
		SCE_DBG_LOG_ERROR("High halfword check failed");
		return -1;
	}

	// decode
	int S = (op_lo & 0x0400) >> 10;
	int J1 = (op_hi & 0x2000) >> 13;
	int J2 = (op_hi & 0x0800) >> 11;
	int I1 = ~(J1 ^ S) & 1;
	int I2 = ~(J2 ^ S) & 1;
	int imm10 = op_lo & 0x03FF;
	int imm11 = op_hi & 0x07FF;

	// combine to 25 bits and sign extend
	*imm = (S << 31) | (I1 << 30) | (I2 << 29) | (imm10 << 19) | (imm11 << 8);
	*imm >>= 7;

	SCE_DBG_LOG_INFO("BL %04hX %04hX decoded with immediate 0x%08X", op_lo, op_hi, *imm);
	return 0;
}

static int decode_blx_t2(uint16_t op_lo, uint16_t op_hi, int *imm) {
	return decode_bl_common(op_lo, op_hi, imm, 0xF800, 0xF000, 0xD001, 0xC000);
}

int get_addr_blx(uint16_t *pc, uint16_t **addr) {
	int ret;
	int offset = 0;
	if ((ret = decode_blx_t2(pc[0], pc[1], &offset)) < 0) {
		return ret;
	}

	// PC is one word ahead and aligned backwards to word boundary
	*addr = pc + 2 - ((uintptr_t)pc % 4 ? 1 : 0) + offset/2;

	SCE_DBG_LOG_INFO("BLX at %p branches to %p", pc, *addr);
	return 0;
}
