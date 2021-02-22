#ifndef SCEPAF_H_
#define SCEPAF_H_

#include <gxm.h>

typedef struct {
	void *vptr;
	int unk4;
	int unk8;
	SceUInt32 resource_id;
} ScePafResourceId;

typedef struct {
	SceGxmTexture *texture;
	int unk4;
} ScePafGxmTexture;

typedef struct ScePafTextureBase {
	struct ScePafTextureBase *prev;
	struct ScePafTextureBase *next;
	int lock;
	short width;
	short height;
	int unk10;
	int unk14;
	int unk18;
	short width2;
	short height2;
	float x_scale;
	float y_scale;
	int pixels;
	short width3;
	short unk3e;
	int unk30;
	ScePafGxmTexture *texture;
	int unk38;
	int unk3c;
	int unk40;
	int unk44;
	int unk48;
	int unk4c;
	int unk50;
	int unk54;
	int unk58;
	int *gxm_data;
} ScePafTextureBase;

typedef struct {
	void *vptr;
	int unk4;
	int unk8;
	int unkc;
	ScePafTextureBase base;
	// full size is 0x94
} ScePafTexture;

#endif
