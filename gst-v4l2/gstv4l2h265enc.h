/*
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

#ifndef __GST_V4L2_H265_ENC_H__
#define __GST_V4L2_H265_ENC_H__

#include <gst/gst.h>
#include "gstv4l2videoenc.h"

G_BEGIN_DECLS
#define GST_TYPE_V4L2_H265_ENC \
  (gst_v4l2_h265_enc_get_type())
#define GST_V4L2_H265_ENC(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_V4L2_H265_ENC,GstV4l2H265Enc))
#define GST_V4L2_H265_ENC_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_V4L2_H265_ENC,GstV4l2H265EncClass))
#define GST_IS_V4L2_H265_ENC(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_V4L2_H265_ENC))
#define GST_IS_V4L2_H265_ENC_CLASS(obj) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_V4L2_H265_ENC))
typedef struct _GstV4l2H265Enc GstV4l2H265Enc;
typedef struct _GstV4l2H265EncClass GstV4l2H265EncClass;

struct _GstV4l2H265Enc
{
  GstV4l2VideoEnc parent;
  gboolean insert_sps_pps;
  guint profile;
  guint nBFrames;
  guint nRefFrames;
  gboolean insert_aud;
  gboolean insert_vui;
  gboolean extended_colorformat;
  guint SliceIntraRefreshInterval;
  gboolean EnableTwopassCBR;
  gboolean bit_packetization;
  guint32 slice_header_spacing;
  gboolean EnableMVBufferMeta;
  gboolean enableLossless;
};

struct _GstV4l2H265EncClass
{
  GstV4l2VideoEncClass parent_class;
};

GType gst_v4l2_h265_enc_get_type (void);

gboolean gst_v4l2_is_h265_enc (GstCaps * sink_caps, GstCaps * src_caps);

void gst_v4l2_h265_enc_register (GstPlugin * plugin, const gchar * basename,
    const gchar * device_path, GstCaps * sink_caps, GstCaps * src_caps);

G_END_DECLS
#endif /* __GST_V4L2_H265_ENC_H__ */
