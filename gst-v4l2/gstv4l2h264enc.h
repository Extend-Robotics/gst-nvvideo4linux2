/*
 * Copyright (C) 2014 SUMOMO Computer Association.
 *     Author: ayaka <ayaka@soulik.info>
 * Copyright (c) 2018-2021, NVIDIA CORPORATION. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifndef __GST_V4L2_H264_ENC_H__
#define __GST_V4L2_H264_ENC_H__

#include <gst/gst.h>
#include "gstv4l2videoenc.h"

G_BEGIN_DECLS
#define GST_TYPE_V4L2_H264_ENC \
  (gst_v4l2_h264_enc_get_type())
#define GST_V4L2_H264_ENC(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_V4L2_H264_ENC,GstV4l2H264Enc))
#define GST_V4L2_H264_ENC_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_V4L2_H264_ENC,GstV4l2H264EncClass))
#define GST_IS_V4L2_H264_ENC(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_V4L2_H264_ENC))
#define GST_IS_V4L2_H264_ENC_CLASS(obj) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_V4L2_H264_ENC))
typedef struct _GstV4l2H264Enc GstV4l2H264Enc;
typedef struct _GstV4l2H264EncClass GstV4l2H264EncClass;

struct _GstV4l2H264Enc
{
  GstV4l2VideoEnc parent;
#ifdef USE_V4L2_TARGET_NV
  guint profile;
  guint nBFrames;
  guint nRefFrames;
  gboolean insert_sps_pps;
  gboolean insert_aud;
  gboolean insert_vui;
  gboolean extended_colorformat;
  gboolean EnableTwopassCBR;
  gboolean SliceIntraRefreshEnable;
  guint SliceIntraRefreshInterval;
  gboolean disable_cabac_entropy_coding;
  gboolean bit_packetization;
  guint32 slice_header_spacing;
  gboolean EnableMVBufferMeta;
  guint poc_type;
  gboolean enableLossless;
#endif
};

struct _GstV4l2H264EncClass
{
  GstV4l2VideoEncClass parent_class;
};

GType gst_v4l2_h264_enc_get_type (void);

gboolean gst_v4l2_is_h264_enc (GstCaps * sink_caps, GstCaps * src_caps);

void gst_v4l2_h264_enc_register (GstPlugin * plugin, const gchar * basename,
    const gchar * device_path, GstCaps * sink_caps, GstCaps * src_caps);

G_END_DECLS
#endif /* __GST_V4L2_H264_ENC_H__ */
