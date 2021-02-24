/*
	Copyright (C) 2019-2021 Reiko Asakura. All Rights Reserved.

	Fruitpeel
*/

#ifndef PATCH_H_
#define PATCH_H_

#include <taihen.h>

#define HOOK_OFFSET(modid, segidx, offset, thumb, func) \
	hook_offset(modid, segidx, offset, thumb, func##_hook, &func##_hook_id, &func##_hook_ref, #func)

#define UNHOOK(func) unhook(&func##_hook_id, func##_hook_ref, #func)

#define INJECT_DATA(modid, segidx, offset, data, size, name) \
	inject_data(modid, segidx, offset, data, size, &name##_id, #name)

#define UNINJECT(name) uninject(&name##_id, #name)

int hook_offset(
	SceUID modid, int segidx, int offset, int thumb, void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name);

int unhook(SceUID *hook_id, tai_hook_ref_t hook_ref, const char *name);

int inject_data(
	SceUID modid, int segidx, int offset, const void *data, size_t size,
	SceUID *inject_id, const char *name);

int uninject(SceUID *inject_id, const char *name);

#endif
