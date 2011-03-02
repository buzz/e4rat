/*
 * defrag.hh - Operations on relevant file defragmentation
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

#ifndef DEFRAG_HH
#define DEFRAG_HH

#include "common.hh"
#include "fileptr.hh"
#include "device.hh"

#include <vector>
#include <string>

#include <ext2fs/ext2fs.h>
#include <ext2fs/ext2_fs.h>

struct OrigDonorPair
{
        OrigDonorPair()
        {
            blocks = 0;
        }
        fs::path origPath;
        fs::path donorPath;
        __u64 blocks;
};

class Defrag : public InterruptAble
{
        typedef std::vector<fs::path> filelist_t;
    protected:
        Defrag();
        bool doesKernelSupportPA(Device&);
        bool isPAenabled(fs::path& mountPoint, char* device_name);
        void createDonorFiles_PA(
                        Device& device,
                        std::vector<OrigDonorPair>& files);
        void fillUpLocalityGroup(Device& device);
        void createDonorFiles_LocalityGroup(
                        Device& device,
                        std::vector<OrigDonorPair>& files);
        void createDonorFiles_TLD(
                        Device& device,
                        std::vector<OrigDonorPair>& files);
        void createDonorFiles(
                        Device& device,
                        std::vector<OrigDonorPair>& defragPair );

        std::vector<OrigDonorPair>
        checkFilesAttributes(filelist_t&);
        
        void defragRelatedFiles(Device& device, std::vector<OrigDonorPair>& files);

        int invalid_file_type;
        int not_writable;
        int not_extent_based;
        int empty_files;
};

class Optimizer : public Defrag
{
    public:
        Optimizer();
        void relatedFiles(std::vector<fs::path>&);
};

#endif
