/*
	Copyright (C) 2019-2021 Reiko Asakura. All Rights Reserved.

	Fruitpeel
*/

#include <libdbg.h>

#include "patch.h"

/* ARGSUSED */
int hook_offset(
	SceUID modid, int segidx, int offset, int thumb, void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name)
{
	*hook_id = taiHookFunctionOffset(hook_ref, modid, segidx, offset, thumb, func);
	if (*hook_id < 0) {
		SCE_DBG_LOG_ERROR("Failed to hook %s %08X", name, *hook_id);
	} else {
		SCE_DBG_LOG_INFO("Hooked %s %08X", name, *hook_id);
	}
	return *hook_id;
}

/* ARGSUSED */
int unhook(SceUID *hook_id, tai_hook_ref_t hook_ref, const char *name) {
	int ret = SCE_OK;
	if (*hook_id < 0) {
		SCE_DBG_LOG_WARNING("Skipped unhooking %s %08X", name, *hook_id);
	} else {
		ret = taiHookRelease(*hook_id, hook_ref);
		if (ret == SCE_OK) {
			SCE_DBG_LOG_INFO("Unhooked %s %08X", name, *hook_id);
			*hook_id = -1;
		} else {
			SCE_DBG_LOG_ERROR("Failed to unhook %s %08X %08X", name, *hook_id, ret);
		}
	}
	return ret;
}
