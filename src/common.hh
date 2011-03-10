/*
 * common.hh - Collection of common functions and classes 
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

#ifndef COMMON_HH
#define COMMON_HH

#include <linux/types.h>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>

#define STARTUP_LOG_FILE "/var/lib/"PROGRAM_NAME"/startup.log"

namespace fs = boost::filesystem;

void setStdIn2NonBlocking();

/*
 * Path operations
 */
const boost::regex path2regex(std::string path);
std::vector<std::string> matchPath( const std::string & filesearch );
fs::path realpath(fs::path _path, fs::path _cwd = "");
fs::path resolvSymLink(fs::path link);

/*
 * operations on file descriptor
 */
int funlink(int fd);
std::string getPathFromFd(int fd);

/*
 * get mount-point by parsing /etc/mtab
 */
int get_mount_point(const char *devname, char *mount_point,
                           int dir_path_len);

pid_t readPidFile(const char* path);
bool createPidFile(const char* path);

/*
 * UserInterrupt is an exception thrown on non-multi-threaded application
 * its job is to clean up memory and other system resources
 * throwing exception for interruption allows us to be compatible
 * with boost threads
 */
class UserInterrupt : public std::exception
{
    public:
        UserInterrupt()
            : msg("User interrupt.")
        {}
        virtual const char* what() const throw()

        {
            return msg;
        }
    private:
        const char* msg;
};

class InterruptAble
{
    public:
        static void interrupt();
    protected:
        void interruptionPoint();
    private:
        static const char* message;
        static bool interrupted;
};

void signalHandler(int signum);

#endif
