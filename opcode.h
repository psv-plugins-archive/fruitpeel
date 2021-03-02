/*
	Copyright (C) 2019-2021 Reiko Asakura. All Rights Reserved.

	Fruitpeel
*/

#ifndef OPCODE_H_
#define OPCODE_H_

#include <stdint.h>

int get_addr_blx(uint16_t *pc, uint16_t **addr);

#endif
