/*
 * fiemap.cc - get physical block mapping
 *
 * Copyright (C) 2011 by Andreas Rid
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "fiemap.hh"
#include "logging.hh"

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

/*
 * Call fiemap ioctl on file descriptor fd.
 * Determine the size of struct fiemap by extent_count.
 * If extent_count is set to 0, it chooses the size by itself to receive all extents.
 *
 * Returns NULL on error
 */
struct fiemap* ioctl_fiemap(int fd, unsigned int extent_count)
{
    int do_realloc = 0;
    if(!extent_count)
    {
        extent_count = 10;
        do_realloc = 1;
    }
    
    struct fiemap* fmap = (struct fiemap*)calloc(1, 
                sizeof(struct fiemap) + extent_count * sizeof(struct fiemap_extent));

    fmap->fm_length = FIEMAP_MAX_OFFSET;
    fmap->fm_flags |= FIEMAP_FLAG_SYNC;
    fmap->fm_extent_count = extent_count;

    if(ioctl(fd, FS_IOC_FIEMAP, fmap) < 0)
    {
        char __filename[PATH_MAX];
        char __path2fd[1024];
        
        sprintf(__path2fd, "/proc/self/fd/%d", fd);
        int len;
        if((len = readlink(__path2fd, __filename, PATH_MAX)) != -1)
        {
            __filename[len] = '\0';    
            error("ioctl_fiemap: %s: %s", __filename, strerror(errno));
        }
        else
            error("ioctl_fiemap and readlink failed: %s", strerror(errno));
        
        free(fmap);
        return NULL;
    }
    
    if(do_realloc)
    {
        if(fmap->fm_mapped_extents == fmap->fm_extent_count)
            fmap = ioctl_fiemap(fd, extent_count<<4);
        
        fmap = (struct fiemap*) realloc(fmap, sizeof(struct fiemap) 
                            + fmap->fm_mapped_extents  * sizeof(struct fiemap_extent));
        fmap->fm_extent_count = fmap->fm_mapped_extents;
    }
    
    return fmap;
}

/*
 * Return struct fiemap by calling ioctl_fiemap
 */
struct fiemap* get_fiemap(const char* file)
{
    int fd;
    fd = open64(file, O_RDONLY);
    if (fd < 0)
    {
        error("open: %s: %s", file, strerror(errno));
        return NULL;
    }
    struct fiemap* fmap = ioctl_fiemap(fd, 0);
    close(fd);
    return fmap;
}

/*
 * Calculating physical block count of inode
 */
__u64 get_block_count(int fd)
{
    __u64 result = 0;
    struct fiemap* fmap;
    
    fmap = ioctl_fiemap(fd, 0);
    if(NULL == fmap)
        return result;
    
    for(unsigned int j=0; j < fmap->fm_mapped_extents; j++)
        result += fmap->fm_extents[j].fe_length >> 12;
    
    return result;
}

__u32 get_frag_count(int fd)
{
    struct fiemap* fmap;
    
    fmap = ioctl_fiemap(fd, 0);
    if(NULL == fmap)
        return 0;
    return fmap->fm_mapped_extents;
}
