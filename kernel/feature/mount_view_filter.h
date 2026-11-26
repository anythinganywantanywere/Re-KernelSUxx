// SPDX-License-Identifier: GPL-2.0
/*
 * mount_view_filter.h - Mount view filter for proc mounts
 *
 * Adapted from FinaSU (kernel/feature/mount_view_filter.h). Only the
 * init return type differs: alpha's kernelsu_init() expects int,
 * following ksu_uts_view_init().
 */
#ifndef __KSU_H_MOUNT_VIEW_FILTER
#define __KSU_H_MOUNT_VIEW_FILTER

int __init ksu_mvf_init(void);
void ksu_mvf_exit(void);

#endif /* __KSU_H_MOUNT_VIEW_FILTER */
