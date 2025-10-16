/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#pragma once

#include "lib/utils.h"

#define CLUSTER_ID_LOWER_MASK 0x000000FF

#ifndef __CLUSTERMESH_HELPERS__
#define __CLUSTERMESH_HELPERS__
/* these macros allow us to override the values in tests */
// #define IDENTITY_LEN get_identity_len()
#define IDENTITY_MAX get_max_identity()

DECLARE_CONFIG(__u32, clustermesh_identity_length, "Cluster mesh identity length, in bits")
DECLARE_CONFIG(__u32, clustermesh_identity_max, "Maximum cluster mesh identity value")

static __always_inline __u32
get_identity_len()
{
	__u32 identity_len = CONFIG(clustermesh_identity_length);
	return identity_len;
}

#endif /* __CLUSTERMESH_HELPERS__ */


static __always_inline __u32
extract_cluster_id_from_identity(__u32 identity)
{
	return (__u32)(identity >> get_identity_len());
}

static __always_inline __u32
get_max_identity()
{
	return (__u32)((1 << get_identity_len()) - 1);
}

static __always_inline __maybe_unused __u32
get_cluster_id_upper_mask()
{
	return (CLUSTER_ID_MAX & ~CLUSTER_ID_LOWER_MASK) << (8 + get_identity_len());
}

static __always_inline __maybe_unused __u32
get_mark_magic_cluster_id_mask()
{
	return CLUSTER_ID_LOWER_MASK | get_cluster_id_upper_mask();
}
