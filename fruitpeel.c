/*
	Copyright (C) 2019-2021 Reiko Asakura. All Rights Reserved.

	Fruitpeel
*/

#include <gxm.h>
#include <kernel/constant.h>
#include <kernel/iofilemgr.h>
#include <kernel/modulemgr.h>
#include <kernel/sysmem.h>
#include <libdbg.h>
#include <libsysmodule.h>
#include <scepng.h>
#include <taihen.h>

#include "scepaf.h"

/* ARGSUSED */
static int hook_import(
	const char *mod, int libnid, int funcnid, void *func,
	SceUID *hook_id, tai_hook_ref_t *hook_ref, const char *name)
{
	*hook_id = taiHookFunctionImport(hook_ref, mod, libnid, funcnid, func);
	if (*hook_id < 0) {
		SCE_DBG_LOG_ERROR("Failed to hook %s %08X", name, *hook_id);
	} else {
		SCE_DBG_LOG_INFO("Hooked %s %08X", name, *hook_id);
	}
	return *hook_id;
}

#define HOOK_IMPORT(mod, libnid, funcnid, func) \
	hook_import(mod, libnid, funcnid, func##_hook, &func##_hook_id, &func##_hook_ref, #func)

/* ARGSUSED */
static int unhook(SceUID *hook_id, tai_hook_ref_t hook_ref, const char *name) {
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

#define UNHOOK(func) \
	unhook(&func##_hook_id, func##_hook_ref, #func)

static SceUID sceSysmoduleLoadModuleInternalWithArg_hook_id = -1;
static tai_hook_ref_t sceSysmoduleLoadModuleInternalWithArg_hook_ref;
static SceUID scePafToplevelGetResourceTexture_hook_id = -1;
static tai_hook_ref_t scePafToplevelGetResourceTexture_hook_ref;

#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

#define FRUITPEEL_PNG "ur0:data/fruitpeel.png"

static SceGxmTexture *blue_tex = NULL;
static int old_width = 0, old_height = 0;
static void *old_tex_buffer = NULL, *old_palette_buffer = NULL;

static SceUID tex_mem_id = -1;
static int tex_mem_size = 0;
static void *tex_buffer = NULL;
static int width = 0, height = 0;

static int scePafToplevelGetResourceTexture_hook(ScePafTexture **tex, int r1, ScePafResourceId *id) {
	int ret = TAI_NEXT(
		scePafToplevelGetResourceTexture_hook, scePafToplevelGetResourceTexture_hook_ref,
		tex, r1, id);

	if (!blue_tex && id && id->resource_id == 0xCA707736 && tex && *tex && (*tex)->base.texture) {
		SCE_DBG_LOG_INFO("RCO GIM texture %08X found", id->resource_id);

		int ret2 = sceGxmMapMemory(tex_buffer, tex_mem_size, SCE_GXM_MEMORY_ATTRIB_READ);
		if (ret2 < 0) {
			SCE_DBG_LOG_ERROR("Failed to map texture memory to GPU %08X", ret2);
			goto done;
		}

		blue_tex = (*tex)->base.texture->texture;
		old_palette_buffer = sceGxmTextureGetPalette(blue_tex);
		old_tex_buffer = sceGxmTextureGetData(blue_tex);
		old_width = sceGxmTextureGetWidth(blue_tex);
		old_height = sceGxmTextureGetHeight(blue_tex);

		sceGxmTextureSetPalette(blue_tex, tex_buffer);
		sceGxmTextureSetData(blue_tex, (char *)tex_buffer + (4<<8));
		sceGxmTextureSetWidth(blue_tex, width);
		sceGxmTextureSetHeight(blue_tex, height);
	}

done:
	return ret;
}

static int sceSysmoduleLoadModuleInternalWithArg_hook(SceUInt32 id, SceSize args, void *argp, void *unk) {
	int ret = TAI_NEXT(
		sceSysmoduleLoadModuleInternalWithArg_hook, sceSysmoduleLoadModuleInternalWithArg_hook_ref,
		id, args, argp, unk);

	if (scePafToplevelGetResourceTexture_hook_id < 0 && ret == SCE_OK && id == SCE_SYSMODULE_INTERNAL_PAF) {
		HOOK_IMPORT("SceShell", 0x4D9A9DD0, 0x38FFFE8E, scePafToplevelGetResourceTexture);
	}

	return ret;
}

static int read_png_file(SceUID *file_mem_id, void **file_buffer, int *file_size) {
	int ret = 0;
	SceUID fd = -1;

	// Check file size
	SceIoStat stat;
	ret = sceIoGetstat(FRUITPEEL_PNG, &stat);
	if (ret < 0) {
		SCE_DBG_LOG_ERROR("Failed to stat " FRUITPEEL_PNG " %08X", ret);
		goto fail;
	}
	if (stat.st_size > SCE_KERNEL_512KiB) {
		SCE_DBG_LOG_ERROR(FRUITPEEL_PNG " is too big %llu", stat.st_size);
		goto fail;
	}
	*file_size = stat.st_size;

	// Allocate file buffer
	*file_mem_id = sceKernelAllocMemBlock(
		"FruitpeelFileBuffer",
		SCE_KERNEL_MEMBLOCK_TYPE_USER_RW,
		ALIGN(*file_size, SCE_KERNEL_4KiB),
		NULL);
	if (*file_mem_id < 0) {
		SCE_DBG_LOG_ERROR("Failed to allocate file memory %08X", *file_mem_id);
		goto fail;
	}
	sceKernelGetMemBlockBase(*file_mem_id, file_buffer);

	// Read PNG file
	fd = sceIoOpen(FRUITPEEL_PNG, SCE_O_RDONLY, 0);
	if (fd < 0) {
		SCE_DBG_LOG_ERROR("Failed to open " FRUITPEEL_PNG " %08X", fd);
		goto fail2;
	}
	ret = sceIoRead(fd, *file_buffer, *file_size);
	sceIoClose(fd);
	if (ret != *file_size) {
		SCE_DBG_LOG_ERROR("Failed to read " FRUITPEEL_PNG " %08X", ret);
		goto fail2;
	}
	SCE_DBG_LOG_INFO(FRUITPEEL_PNG " read %u bytes", ret);

	return 0;

fail2:
	sceKernelFreeMemBlock(*file_mem_id);
fail:
	return -1;
}

static int decode_png_file(void *file_buffer, int file_size) {
	int ret = 0;

	// Check PNG info
	int output_format, stream_format;
	ret = scePngGetOutputInfo(file_buffer, file_size, &width, &height, &output_format, &stream_format);
	if (ret < 0) {
		SCE_DBG_LOG_ERROR("Failed to get PNG info %08X", ret);
		goto fail;
	}
	if (width % 8 != 0) {
		SCE_DBG_LOG_ERROR("Width is not a multiple of 8 %u", width);
		goto fail;
	}
	if (output_format != SCE_PNG_FORMAT_CLUT8) {
		SCE_DBG_LOG_ERROR("Wrong PNG format %08X", output_format);
		goto fail;
	}

	// Allocate decode buffer
	tex_mem_size = ALIGN(((width*8+7)/8+1)*height + (4<<8), SCE_KERNEL_4KiB);
	tex_mem_id = sceKernelAllocMemBlock(
		"FruitpeelTextureData",
		SCE_KERNEL_MEMBLOCK_TYPE_USER_NC_RW,
		tex_mem_size,
		NULL);
	if (tex_mem_id < 0) {
		SCE_DBG_LOG_ERROR("Failed to allocate texture memory %08X", tex_mem_id);
		goto fail;
	}
	sceKernelGetMemBlockBase(tex_mem_id, &tex_buffer);

	// Decode PNG
	ret = scePngDec(tex_buffer, tex_mem_size, file_buffer, file_size, &width, &height, &output_format);
	if (ret < 0) {
		SCE_DBG_LOG_ERROR("Failed to decode PNG %08X", ret);
		goto fail2;
	}
	SCE_DBG_LOG_INFO("Decoded PNG %ux%u", width, height);

	return 0;

fail2:
	sceKernelFreeMemBlock(tex_mem_id);
	tex_mem_id = -1;
fail:
	return -1;
}

static void cleanup(void) {
	UNHOOK(sceSysmoduleLoadModuleInternalWithArg);
	UNHOOK(scePafToplevelGetResourceTexture);

	if (blue_tex) {
		sceGxmTextureSetWidth(blue_tex, old_width);
		sceGxmTextureSetHeight(blue_tex, old_height);
		sceGxmTextureSetPalette(blue_tex, old_palette_buffer);
		sceGxmTextureSetData(blue_tex, old_tex_buffer);
		blue_tex = NULL;
	}

	if (tex_mem_id >= 0) {
		sceKernelFreeMemBlock(tex_mem_id);
		tex_mem_id = -1;
	}
}

int module_start() {
	int ret = 0;

	SceUID file_mem_id = 0;
	void *file_buffer = NULL;
	int file_size = 0;
	if (read_png_file(&file_mem_id, &file_buffer, &file_size) < 0) {
		goto fail;
	}

	ret = decode_png_file(file_buffer, file_size);
	sceKernelFreeMemBlock(file_mem_id);
	if (ret < 0) {
		goto fail;
	}

	if (HOOK_IMPORT("SceShell", 0x03FCF19D, 0xC3C26339, sceSysmoduleLoadModuleInternalWithArg) < 0) {
		goto fail;
	}

	return SCE_KERNEL_START_SUCCESS;

fail:
	cleanup();
	return SCE_KERNEL_START_FAILED;
}

int module_stop() {
	cleanup();
	return SCE_KERNEL_STOP_SUCCESS;
}
