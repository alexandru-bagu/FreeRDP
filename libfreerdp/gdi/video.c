/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Video Optimized Remoting Virtual Channel Extension for X11
 *
 * Copyright 2017 David Fort <contact@hardening-consulting.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../core/update.h"

#include <winpr/assert.h>

#include <freerdp/client/geometry.h>
#include <freerdp/client/video.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/gdi/video.h>
#include <freerdp/gdi/region.h>

#define TAG FREERDP_TAG("video")

typedef struct
{
	VideoSurface base;
	UINT32 scanline;
	BYTE* image;
} gdiVideoSurface;

void gdi_video_geometry_init(rdpGdi* gdi, GeometryClientContext* geom)
{
	WINPR_ASSERT(gdi);
	WINPR_ASSERT(geom);

	gdi->geometry = geom;

	if (gdi->video)
	{
		VideoClientContext* video = gdi->video;

		WINPR_ASSERT(video);
		WINPR_ASSERT(video->setGeometry);
		video->setGeometry(video, gdi->geometry);
	}
}

void gdi_video_geometry_uninit(rdpGdi* gdi, GeometryClientContext* geom)
{
}

static VideoSurface* gdiVideoCreateSurface(VideoClientContext* video, BYTE* data, DWORD format,
                                           UINT32 x, UINT32 y, UINT32 width, UINT32 height)
{
	rdpGdi* gdi;
	gdiVideoSurface* ret;
	UINT32 bpp;

	WINPR_ASSERT(video);

	gdi = (rdpGdi*)video->custom;
	WINPR_ASSERT(gdi);

	ret = calloc(1, sizeof(gdiVideoSurface));
	if (!ret)
		return NULL;

	bpp = GetBytesPerPixel(format);
	ret->base.format = format;
	ret->base.data = data;
	ret->base.x = x;
	ret->base.y = y;
	ret->base.w = width;
	ret->base.h = height;
	ret->scanline = width * bpp;
	ret->image = _aligned_malloc(ret->scanline * height * 1ULL, 16);

	if (!ret->image)
	{
		WLog_ERR(TAG, "unable to create surface image");
		free(ret);
		return NULL;
	}

	return &ret->base;
}

static BOOL gdiVideoShowSurface(VideoClientContext* video, const VideoSurface* surface)
{
	BOOL rc = FALSE;
	rdpGdi* gdi;
	const gdiVideoSurface* gdiSurface = (const gdiVideoSurface*)surface;
	RECTANGLE_16 surfaceRect;
	rdpUpdate* update;

	WINPR_ASSERT(video);
	WINPR_ASSERT(surface);

	gdi = (rdpGdi*)video->custom;
	WINPR_ASSERT(gdi);
	WINPR_ASSERT(gdi->context);

	update = gdi->context->update;
	WINPR_ASSERT(update);

	surfaceRect.left = surface->x;
	surfaceRect.top = surface->y;
	surfaceRect.right = surface->x + surface->w;
	surfaceRect.bottom = surface->y + surface->h;

	if (!update_begin_paint(update))
		goto fail;

	if ((gdi->width < 0) || (gdi->height < 0))
		goto fail;
	else
	{
		const UINT32 nXSrc = surface->x;
		const UINT32 nYSrc = surface->y;
		const UINT32 nXDst = nXSrc;
		const UINT32 nYDst = nYSrc;
		const UINT32 width = (surface->w + surface->x < (UINT32)gdi->width)
		                         ? surface->w
		                         : (UINT32)gdi->width - surface->x;
		const UINT32 height = (surface->h + surface->y < (UINT32)gdi->height)
		                          ? surface->h
		                          : (UINT32)gdi->height - surface->y;

		WINPR_ASSERT(gdi->primary_buffer);
		WINPR_ASSERT(gdi->primary);
		WINPR_ASSERT(gdi->primary->hdc);
		if (!freerdp_image_copy(gdi->primary_buffer, gdi->primary->hdc->format, gdi->stride, nXDst,
		                        nYDst, width, height, surface->data, surface->format,
		                        gdiSurface->scanline, 0, 0, NULL, FREERDP_FLIP_NONE))
			goto fail;

		if ((nXDst > INT32_MAX) || (nYDst > INT32_MAX) || (width > INT32_MAX) ||
		    (height > INT32_MAX))
			goto fail;

		gdi_InvalidateRegion(gdi->primary->hdc, (INT32)nXDst, (INT32)nYDst, (INT32)width,
		                     (INT32)height);
	}

	rc = TRUE;
fail:

	if (!update_end_paint(update))
		return FALSE;

	return rc;
}

static BOOL gdiVideoDeleteSurface(VideoClientContext* video, VideoSurface* surface)
{
	gdiVideoSurface* gdiSurface = (gdiVideoSurface*)surface;

	if (gdiSurface)
		_aligned_free(gdiSurface->image);

	free(gdiSurface);
	return TRUE;
}
void gdi_video_control_init(rdpGdi* gdi, VideoClientContext* video)
{
	WINPR_ASSERT(gdi);
	WINPR_ASSERT(video);

	gdi->video = video;
	video->custom = gdi;
	video->createSurface = gdiVideoCreateSurface;
	video->showSurface = gdiVideoShowSurface;
	video->deleteSurface = gdiVideoDeleteSurface;
	video->setGeometry(video, gdi->geometry);
}

void gdi_video_control_uninit(rdpGdi* gdi, VideoClientContext* video)
{
	WINPR_ASSERT(gdi);
	gdi->video = NULL;
}

static void gdi_video_timer(void* context, TimerEventArgs* timer)
{
	rdpContext* ctx = (rdpContext*)context;
	rdpGdi* gdi;

	WINPR_ASSERT(ctx);
	WINPR_ASSERT(timer);

	gdi = ctx->gdi;

	if (gdi && gdi->video)
		gdi->video->timer(gdi->video, timer->now);
}

void gdi_video_data_init(rdpGdi* gdi, VideoClientContext* video)
{
	WINPR_ASSERT(gdi);
	WINPR_ASSERT(gdi->context);
	PubSub_SubscribeTimer(gdi->context->pubSub, gdi_video_timer);
}

void gdi_video_data_uninit(rdpGdi* gdi, VideoClientContext* context)
{
	WINPR_ASSERT(gdi);
	WINPR_ASSERT(gdi->context);
	PubSub_UnsubscribeTimer(gdi->context->pubSub, gdi_video_timer);
}
