/*
 * fileoffset.cc - display physical block allocation and their offset
 *                 of a list of files
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

#include "common.hh"
#include "fiemap.hh"
#include <iostream>
#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <linux/limits.h>
#include <boost/foreach.hpp>

bool isNumeric(const char *p)
{
    for ( ; *p; p++)
        if (*p < '0' || *p > '9')
            return false;
    return true;
}

void setStdIn2NonBlocking()
{
    int cinfd = fileno(stdin);
    const int fcflags = fcntl(cinfd,F_GETFL);
    if (fcflags<0)
    {
        std::cerr << "Cannot read flags of stdin\n";
    }
    if (fcntl(cinfd,F_SETFL,fcflags | O_NONBLOCK) <0)
    {
        std::cerr << "Cannot set stdin to non-blocking\n";
    } 
    std::cin.exceptions ( std::ifstream::eofbit
                          | std::ifstream::failbit
                          | std::ifstream::badbit );
}

void parseArguemntList(int argc, char* argv[], std::vector<std::string>& filelist)
{
    if(optind < argc)
    {
        if(isNumeric(argv[optind]))
        {
            for ( ; optind < argc - 2; optind +=3)
                filelist.push_back(argv[optind+2]);
            if(optind != argc)
            {
                std::cout << "Error parsing input values\n";
            }
        }
        else
            for ( ; optind < argc; optind++)
                filelist.push_back(argv[optind]);
    }
}

void parseInputStream(std::istream& in, std::vector<std::string>& filelist)
{
    int td = 0;
    ino_t ti;
    char tp[PATH_MAX];
    
    setStdIn2NonBlocking();
    
    try {
        if(std::cin.peek() == '/')
            while(!std::cin.eof())
            {
                std::cin >> tp;
                filelist.push_back(tp);
            }
        else
            while(1)
            {
                std::cin >> td;
                std::cin >> ti;
                std::cin >> tp;
                filelist.push_back(tp);
            }
    }
    catch(...)
    {}
}

void printUsage()
{
    std::cout <<
        "Usage: fileoffset [file(s)]\n"
        ;
}
int main(int argc, char* argv[])
{
    struct fiemap* fmap;
    int fd;
    int prev_block = 0;
    int l = 13;

    
    std::vector<std::string> filelist;
    parseArguemntList(argc, argv, filelist);
    parseInputStream(std::cin, filelist);

    if(filelist.empty())
        goto out;

    printf("%*s%*s%*s%*s%*s   %s\n", 3, "ext", l, "start",l, "end",l, "length", l, "offset", "file");
    
    BOOST_FOREACH(std::string& file, filelist)
    {
        fd = open(file.c_str(), O_RDONLY | O_NOFOLLOW);
        if(-1 == fd)
        {
            std::cerr << "Cannot open file: "
                      << file << ": "
                      << strerror(errno) << std::endl;
            continue;
        }
        
        fmap = ioctl_fiemap(fd);
        if(NULL == fmap)
        {
            std::cerr << "Cannot receive file extents: "
                      << file << ": "
                      << strerror(errno) << std::endl;
            close(fd);
            continue;
        }

        for(__u32 i = 0; i < fmap->fm_mapped_extents; i++)
        {
            int start = fmap->fm_extents[i].fe_physical>>12;
            int end   = start + (fmap->fm_extents[i].fe_length>>12) - 1;
            if(1 == fmap->fm_mapped_extents)
                printf("%*s", 3, " ");
            else
                printf("%*d", 3, i+1);
            printf("%*d", l, start);
            printf("%*d", l, end);
            printf("%*d", l, end - start + 1);
            printf("%*d", l, start - prev_block  -1);
            prev_block = end;
            if(0 == i)
                printf("   %s", file.c_str());
            printf("\n");
                    
        }
        free(fmap);
        close(fd);
    }
    exit(0);
out:
    printUsage();
    exit(1);
}
