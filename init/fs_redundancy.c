/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "log.h"

char bootset[32] = {0};
static const char *secondary = "secondary";

#define NAME_LEN 32

/*
 * This function adds the ability for ueventd to manipulate the expected
 * symlinks for partitions based upon the kernel command line argument
 * of androidboot.bootset.
 *
 * If bootset is passed as primary, everything will be linked as the
 * normal. If bootset is passed as secondary, then the links will
 * be reversed.
 *
 * Example:
 * MBR Layout:
 * mmcblk1p19  -->  system
 * mmcblk1p20  -->  system_secondary
 *
 * If bootset is primary:
 * /dev/block/..../system           --> /dev/block/..../mmcblk1p19
 * /dev/block/..../system_secondary --> /dev/block/..../mmcblk1p20
 *
 * If bootset is secondary:
 * /dev/block/..../system           --> /dev/block/..../mmcblk1p20
 * /dev/block/..../system_secondary --> /dev/block/..../mmcblk1p19
 *
 * This support allows us to maintain two discrete sets of images on disk,
 * and allows us to boot either one based on decisions of the user or
 * based upon certain boot failure conditions.
 */
void get_redundant_partition_alias(const char *action, char *link_path, char *dev_path, char **partition_name)
{
	char *divider = strrchr(*partition_name, '_');
	char primary_name[NAME_LEN] = {'\0'};
	char full_link_path[256] = {'\0'};
	char dest_path[256] = {'\0'};
	ssize_t ret;

	/* If the bootset command line argument isn't present, this function is a no-op */
	if(!bootset[0])
		return;

	if (divider && !strcmp(secondary, divider+1)) {
		/* This is a secondary partition */
		if (!strcmp(bootset, secondary)) {
			/* Secondary partitions should be active */
			if(!strcmp(action, "add")) {
				/* We only need to do cleanup of possibly incorrect symlinks in the add case */
				strncpy(primary_name, *partition_name, (divider-*partition_name));

				snprintf(full_link_path, sizeof(full_link_path)-1, "%s/by-name/%s", link_path, primary_name);
				ret = readlink(full_link_path, dest_path, sizeof(dest_path) - 1);
				if (ret > 0 && strcmp(dest_path, dev_path)) {
					/*
					* The primary partition has already been handled by ueventd, and hence the
					* primary has been incorrectly linked as the active partition. Remove active symlink
					* and make a new link as the inactive partition.
					*/
					unlink(full_link_path);
					snprintf(full_link_path, sizeof(full_link_path)-1, "%s/by-name/%s", link_path, *partition_name);
					make_link(dest_path, full_link_path);
				}

				snprintf(full_link_path, sizeof(full_link_path)-1, "/dev/block/%s", primary_name);
				ret = readlink(full_link_path, dest_path, sizeof(dest_path) - 1);
				if (ret > 0 && strcmp(dest_path, dev_path)) {
					/*
					* The primary partition has already been handled by ueventd, and hence the
					* primary has been incorrectly linked as the active partition. Remove active symlink
					* and make a new link as the inactive partition.
					*/
					unlink(full_link_path);
					snprintf(full_link_path, sizeof(full_link_path)-1, "/dev/block/%s", *partition_name);
					make_link(dest_path, full_link_path);
				}
			}
			/*
			 * Modify passed in partition name so that it appears as primary.
			 * This will cause the ueventd code to treat this device as the
			 * active partition
			 */
			*divider = '\0';
		}
	} else {
		/* This is a primary partition */

		/*
		 * Check to see if the symlink for this primary partition already exists
		 * to a different block device than this one. If it does, that means that
		 * the secondary partition has been linked to the active partition. In this
		 * case we need to treat this as the inactive partition.
		 *
		 * In the removal case, it's also possible that the active link has already
		 * been removed, because it was symlinked to the secondary device. In this
		 * case, we know that the primary device must be inactive.
		 */
		snprintf(full_link_path, sizeof(full_link_path)-1, "%s/by-name/%s", link_path, *partition_name);
		ret = readlink(full_link_path, dest_path, sizeof(dest_path) - 1);
		if ((ret > 0 && strcmp(dest_path, dev_path)) ||
		    (!strcmp(action, "remove") && ret < 0)) {
			char *oldname = *partition_name;
			asprintf(partition_name, "%s_%s", oldname, secondary);
			free(oldname);
		}
	}
}
