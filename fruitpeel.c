/*
	Copyright (C) 2019-2021 Reiko Asakura. All Rights Reserved.

	Fruitpeel
*/

#include <gxm.h>
#include <kernel/constant.h>
#include <kernel/iofilemgr.h>
#include <kernel/libkernel.h>
#include <kernel/modulemgr.h>
#include <kernel/sysmem.h>
#include <libdbg.h>
#include <libsysmodule.h>
#include <scepng.h>
#include <taihen.h>

#include "opcode.h"
#include "scepaf.h"
#include "patch.h"

static SceUID SceShell_uid = 0;
static uint32_t scePafToplevelGetResourceTexture_ofs = 0;
static uint32_t wallpaper_scale_patch_ofs = 0;

static SceUID lockscreen_init_hook_id = -1;
static tai_hook_ref_t lockscreen_init_hook_ref;
static SceUID scePafToplevelGetResourceTexture_hook_id = -1;
static tai_hook_ref_t scePafToplevelGetResourceTexture_hook_ref;
static SceUID wallpaper_scale_patch_id = -1;

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

static int lockscreen_init_hook(int r0, int r1) {
	static int done = 0;

	if (!done) {
		HOOK_OFFSET(SceShell_uid, 0, scePafToplevelGetResourceTexture_ofs, 0, scePafToplevelGetResourceTexture);
	}

	// b 0xE0
	INJECT_DATA(SceShell_uid, 0, wallpaper_scale_patch_ofs, "\x6e\xe0", 2, wallpaper_scale_patch);
	int ret = TAI_NEXT(lockscreen_init_hook, lockscreen_init_hook_ref, r0, r1);
	UNINJECT(wallpaper_scale_patch);

	if (!done && scePafToplevelGetResourceTexture_hook_id >= 0) {
		UNHOOK(scePafToplevelGetResourceTexture);
		done = 1;
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

static int decode_png_file(const void *file_buffer, int file_size, SceUID *decode_buffer_id, void **decode_buffer) {
	int ret = 0;
	int decode_buffer_size = 0;

	// Check PNG info
	int output_format, stream_format;
	ret = scePngGetOutputInfo(file_buffer, file_size, &width, &height, &output_format, &stream_format);
	if (ret < 0) {
		SCE_DBG_LOG_ERROR("Failed to get PNG info %08X", ret);
		goto fail;
	}
	if (width > 896) {
		SCE_DBG_LOG_ERROR("Width is too large %u", width);
		goto fail;
	}
	if (height > 448) {
		SCE_DBG_LOG_ERROR("Height is too large %u", height);
		goto fail;
	}
	if (output_format != SCE_PNG_FORMAT_CLUT8) {
		SCE_DBG_LOG_ERROR("Wrong PNG format %08X", output_format);
		goto fail;
	}

	// Allocate decode buffer
	decode_buffer_size = ALIGN(((width*8+7)/8+1)*height + (4<<8), SCE_KERNEL_4KiB);
	*decode_buffer_id = sceKernelAllocMemBlock(
		"FruitpeelPngDecodeBuffer",
		SCE_KERNEL_MEMBLOCK_TYPE_USER_RW,
		decode_buffer_size,
		NULL);
	if (*decode_buffer_id < 0) {
		SCE_DBG_LOG_ERROR("Failed to allocate PNG decode memory %08X", *decode_buffer_id);
		goto fail;
	}
	sceKernelGetMemBlockBase(*decode_buffer_id, decode_buffer);

	// Decode PNG
	ret = scePngDec(*decode_buffer, decode_buffer_size, file_buffer, file_size, &width, &height, &output_format);
	if (ret < 0) {
		SCE_DBG_LOG_ERROR("Failed to decode PNG %08X", ret);
		goto fail2;
	}
	SCE_DBG_LOG_INFO("Decoded PNG %ux%u", width, height);

	return 0;

fail2:
	sceKernelFreeMemBlock(*decode_buffer_id);
fail:
	return -1;
}

static int create_texture(const void *png_buffer) {

	// Compute margin sizes
	int x_margin = (int)(0.035714 * (float)width);
	int y_margin = (int)(0.071428 * (float)height);
	int stride = ALIGN(2*x_margin+width, 8);

	// Allocate palette and texture data buffer
	tex_mem_size = ALIGN((4<<8) + stride * (2*y_margin+height), SCE_KERNEL_4KiB);
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
	SCE_DBG_LOG_INFO("Texture buffer created size %08X", tex_mem_size);

	// Copy decoded PNG data
	sceClibMemcpy(tex_buffer, png_buffer, 4<<8);
	for (int i = 0; i < height; i++) {
		sceClibMemcpy(
			(char *)tex_buffer + (4<<8) + (i+y_margin)*stride + x_margin,
			(char *)png_buffer + (4<<8) + i*width,
			width);
	}

	width = 2*x_margin + width;
	height = 2*y_margin + height;
	SCE_DBG_LOG_INFO("Texture dimensions %ux%u", width, height);
	return 0;

fail:
	return -1;
}

static void cleanup(void) {
	UNHOOK(lockscreen_init);
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
	SceUID decode_buffer_id = 0;
	void *decode_buffer = NULL;

	tai_module_info_t minfo;
	SceKernelModuleInfo sce_minfo;
	uint32_t SceShell_dbg_fingerprint;
	uint32_t SceShell_seg0;

	uint32_t lockscreen_init_ofs;
	uint32_t lockscreen_init_addr;
	uint16_t *scePafToplevelGetResourceTexture_call_addr;
	uint32_t scePafToplevelGetResourceTexture_addr;

	minfo.size = sizeof(minfo);
	if ((ret = taiGetModuleInfo("SceShell", &minfo)) < 0) {
		SCE_DBG_LOG_ERROR("Failed to get SceShell taiHEN module info %08X", ret);
		goto fail;
	}
	SceShell_uid = minfo.modid;
	SceShell_dbg_fingerprint = minfo.module_nid;

	sce_minfo.size = sizeof(sce_minfo);
	if ((ret = sceKernelGetModuleInfo(SceShell_uid, &sce_minfo)) < 0) {
		SCE_DBG_LOG_ERROR("Failed to get SceShell module info %08X", ret);
		goto fail;
	}
	SceShell_seg0 = (uint32_t)sce_minfo.segments[0].vaddr;

	switch(SceShell_dbg_fingerprint) {
		case 0x0552F692: // 3.60 retail
		case 0x532155E5: // 3.61 retail
			lockscreen_init_ofs = 0x23B7BE;
			break;
		default:
			SCE_DBG_LOG_ERROR("Unsupported SceShell version");
			goto fail;
	}
	lockscreen_init_addr = SceShell_seg0 + lockscreen_init_ofs;
	SCE_DBG_LOG_INFO("lockscreen_init at offset %p", lockscreen_init_ofs);

	wallpaper_scale_patch_ofs = lockscreen_init_ofs - 0x192;
	SCE_DBG_LOG_INFO("wallpaper_scale_patch at offset %p", wallpaper_scale_patch_ofs);

	scePafToplevelGetResourceTexture_call_addr = (uint16_t *)(lockscreen_init_addr + 0x13E);
	if (get_addr_blx(scePafToplevelGetResourceTexture_call_addr, &scePafToplevelGetResourceTexture_addr) < 0) {
		goto fail;
	}
	scePafToplevelGetResourceTexture_ofs = scePafToplevelGetResourceTexture_addr - SceShell_seg0;
	SCE_DBG_LOG_INFO("scePafToplevelGetResourceTexture at offset %p", scePafToplevelGetResourceTexture_ofs);

	if (read_png_file(&file_mem_id, &file_buffer, &file_size) < 0) {
		goto fail;
	}

	ret = decode_png_file(file_buffer, file_size, &decode_buffer_id, &decode_buffer);
	sceKernelFreeMemBlock(file_mem_id);
	if (ret < 0) {
		goto fail;
	}

	ret = create_texture(decode_buffer);
	sceKernelFreeMemBlock(decode_buffer_id);
	if (ret < 0) {
		goto fail;
	}

	if (HOOK_OFFSET(SceShell_uid, 0, lockscreen_init_ofs, 1, lockscreen_init) < 0) {
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
