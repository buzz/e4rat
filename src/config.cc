/*
 * config.cc - global settings and config file parser
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

#include "config.hh"
#include "logging.hh"

#include <fcntl.h>
#include <iostream>

#include <boost/property_tree/info_parser.hpp>
#include <boost/foreach.hpp>

DEFINE_SINGLETON(Config);

Config::Config()
{
    defaultProperty.put("loglevel", Error | Warn);
    defaultProperty.put("verbose",  Error | Warn | Notice);
    defaultProperty.put("ext4_only", true);
    defaultProperty.put("defrag_mode", "auto");
    defaultProperty.put("exclude_open_files", true);
    defaultProperty.put("timeout", 120);
    defaultProperty.put("log_target", "/dev/kmsg");
    defaultProperty.put("init", "/sbin/init");
    defaultProperty.put("force", false);
}

Config::~Config()
{}

void Config::load()
{
    try {
        if(access("/etc/"PROGRAM_NAME".conf", F_OK))
            return;

        read_info("/etc/"PROGRAM_NAME".conf", ptree);
#if 0
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, ptree)
            if(defaultProperty.find(v.first) == defaultProperty.not_found())
                std::cerr << "parse config file: unknown option: " << v.first.c_str() << std::endl;
#endif
    }

    catch(std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
}

void Config::clear()
{
    ptree.clear();
}

void Config::setDefaultSection(std::string sec)
{
    defaultSection = sec;
}
