/*
 * e4rat-collect.cc - Generate file list of relevant files by monitoring programs
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

#include "listener.hh"
#include "common.hh"
#include "config.hh"
#include "eventcatcher.hh"
#include "logging.hh"
#include "parsefilelist.hh"

#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <signal.h>

/* EXT2_SUPER_MAGIC */
#include <ext2fs/ext2_fs.h>

/* exec program */
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include <boost/foreach.hpp>

#define PID_FILE "/dev/.e4rat-collect.pid"

void scanOpenFiles(std::vector<FilePtr>& list)
{
    char buffer[PATH_MAX + 64];
    char path[PATH_MAX];
    ino_t ino;
    int major;
    int minor;

    size_t size_early = list.size();
    debug("Scan open files by calling lsof");
    
    FILE* pFile = popen("lsof -w / | awk '{print $6,$8,$9 }'", "r");
    if(NULL == pFile)
        return;
    int lin = 0;
    while(NULL != fgets (buffer , PATH_MAX+64, pFile))
    {
        lin++;
        if(EOF == sscanf(buffer, "%x%*c%x %llu %s",
                            &major, &minor, (long long unsigned int*)&ino, path))
    {
            error("scan lsof: %s", strerror(errno));
    }

        FilePtr file = FilePtr(makedev(major, minor), ino, path);
        if(file.unique())
            list.push_back(file);
    }
    info("%*d open files", 8, list.size() - size_early);
    pclose(pFile);
}


void excludeFileLists(std::vector<const char*>& files, std::vector<FilePtr>& list)
{
    BOOST_FOREACH(const char* fname, files)
    {
        std::vector<std::string> ex_files = matchPath(fname);
        BOOST_FOREACH(std::string filename, ex_files)
        {
            FILE* file = fopen(filename.c_str(), "r");
            if(file)
            {
                size_t size_early = list.size();
                parseInputStream(file, list);
                info("%*d parsed from %s", 8, list.size() - size_early, filename.c_str());
                fclose(file);
            }
            else
                std::cerr << "Cannot open file list: "
                          << filename << ": " << strerror(errno) << std::endl;
        }
    }
}


void printUsage()
{
    std::cout <<
"Usage: " PROGRAM_NAME "-collect [option(s)] [application(s)]\n"
"\n"
"    -V --version                    print version and exit\n"
"    -h --help                       print help and exit\n"
"    -v --verbose                    increment verbose level\n"
"    -q --quiet                      set verbose level to 0\n"
"    -l --loglevel <number>          set log level\n"
"\n"
"    -k --stop                       kill running collector\n"
"    -x --execute <command>          quit after command has finished\n"
"    -o --output [file]              dump generated file list to file\n"
"    -d --device <dev>               watch a specific device\n"
"                                    [example: /dev/sda?]\n"
"    -D --exclude-device <dev>       exclude device\n"
"    -p --path <path>                restrict watch on path [example: '*/bin/*']\n"
"    -P --exclude-path <path>        exclude filesystem path\n"
"    -L --exclude-list <file>        exclude paths listed in file\n"
"    -e --watch-ext4 [true|false]    watch devices matches ext4 filesystem\n"
"                                    [Default: true]\n"
"    -O --exclude-of [true|false]    exclude open files [Default: true]\n"
"\n"
        ;
}

int main(int argc, char* argv[])
{
    bool create_pid_late = false;
    
    Config::instance()->load();
    Config::instance()->setDefaultSection("collect");

    int loglevel = Config::get<int>("loglevel");
    int verbose  = Config::get<int>("verbose");

    const char* execute  = NULL;
    const char* outPath  = NULL;
    FILE* outStream      = NULL;

    std::deque<FilePtr> filelist;
    std::vector<const char*> exclude_filenames ;

    std::vector<FilePtr> excludeList ;

    ScanFsAccess project;
    Listener listener;

    // excluding file list only affect only if process id is not 1
    if(0 == access("/var/lib/"PROGRAM_NAME"/startup", F_OK))
        exclude_filenames.push_back("/var/lib/"PROGRAM_NAME"/startup");
    
    static struct option long_options[] =
        {
            {"verbose",        no_argument,       0, 'v'},
            {"version",        no_argument,       0, 'V'},
            {"quiet",          no_argument,       0, 'q'},
            {"loglevel",       required_argument, 0, 'l'},
            {"help",           no_argument,       0, 'h'},
            {"exclude-device", required_argument, 0, 'D'},
            {"device",         required_argument, 0, 'd'},
            {"exclude-path",   required_argument, 0, 'P'},
            {"path",           required_argument, 0, 'p'},
            {"exclude-list",   optional_argument, 0, 'L'},
            {"watch-ext4",     required_argument, 0, 'e'},
            {"exclude-of",     required_argument, 0, 'O'},
            {"execute",        required_argument, 0, 'x'},
            {"output",         required_argument, 0, 'o'},
            {"stop",           no_argument,       0, 'k'},
            {0, 0, 0, 0}
        };

    int c;
    int option_index = 0;
    opterr = 0;
    while ((c = getopt_long (argc, argv, "hVvql:o:D:d:P:p:L:e:O:x:k", long_options, &option_index)) != EOF)
    {
        // parse optional arguments
        if(optarg != NULL && optarg[0] == '-')
        {
            optopt = c;
            c = '?';
            --optind;
        }
            

        switch(c)
        {
            case 'h':
                goto err1;
            case 'V':
                std::cout << PROGRAM_NAME << " " << VERSION << std::endl;
                return 0;
            case 'v':
                verbose <<= 1;
                verbose |= 1;
                break;
            case 'q':
                verbose = 0;
                break;
            case 'l':
                loglevel = atoi(optarg);
                break;
            case 'L':
                exclude_filenames.push_back(optarg);
                break;
            case 'o':
                outPath = optarg;
                break;
            case 'D':
                listener.excludeDevice(optarg);
                break;
            case 'd':
                listener.watchDevice(optarg);
                break;
            case 'P':
                listener.excludePath(optarg);
                break;
            case 'p':
                listener.watchPath(optarg);
                break;
            case 'e':
            {
                bool value;
                std::stringstream ss(optarg);
                ss >> std::boolalpha >> value;
                Config::set<bool>("ext4_only", value);
            }
                break;
            case 'O':
            {
                bool value;
                std::stringstream ss(optarg);
                ss >> std::boolalpha >> value;
                Config::set<bool>("exclude_open_files", value);
            }
                break;
            case 'x':
                execute = optarg;
                break;
            case 'k':
            {
                pid_t pid = readPidFile(PID_FILE);
                if(pid)
                    kill(pid, SIGINT);
                return 0;
            }
            //case ':': break;
            case '?':
                if (optopt == 'o') // optional parameter for output is missing
                    outStream = stdout;
                else if(optopt == 'e')
                    Config::set<bool>("ext4_only", true);
                else if(optopt == 'O')
                    Config::set<bool>("exclude_open_files", true);
                else if(optopt == 'L')
                    exclude_filenames.clear();
                else
                {
                    fprintf(stderr, "Option requires an argument -- '%c'\n", optopt);
                    return -1;
                }
                break;
            default:
                std::cerr << "Unrecognised option: " << optopt << std::endl;
                goto err1;
        }
    }

    logger.setVerboseLevel(verbose);
    logger.setLogLevel(loglevel);

    if(getuid() != 0)
    {
        std::cerr << "You need root privileges to run this program.\n";
        return 1;
    }

    /*
     * Register Signalhandler
     */
    struct sigaction sa;
    memset(&sa, '\0', sizeof(struct sigaction));
    sa.sa_handler = signalHandler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if(1 == getpid())
    {
        create_pid_late = true;

        outPath = "/var/lib/"PROGRAM_NAME"/startup";
        verbose = 0;
    }
    else
    {
        if(true == Config::get<bool>("exclude_open_files") || exclude_filenames.size())
        {
            info("Generating exclude file list ...");
            try {
                if(true == Config::get<bool>("exclude_open_files"))
                    scanOpenFiles(excludeList);
                excludeFileLists(exclude_filenames, excludeList);
            }
            catch(std::exception& e)
            {
                std::cout << e.what() << std::endl;
                goto err2;
            }
            info("Total number of excluded files: %d", excludeList.size());
        }
        
        if(!createPidFile(PID_FILE))
        {
            std::cerr << "It seems that e4rat-collect is already running.\n";
            std::cerr << "Remove pid file " << PID_FILE << " to unlock.\n";
            exit(1);
        }
    
        if(outStream == stdout)
            logger.redirectStdout2Stderr(true);
        else if(!outPath)
            outPath = "./e4rat-collect.log";

	/*
         * Parse application list given as arguments
         */
        for ( ; optind < argc; optind++)
            project.observeApp(fs::path(argv[optind]).filename());

        /*
         * Parse application list on stdin
         */
        char app[PATH_MAX];
        setStdIn2NonBlocking();

        try {
            while(!std::cin.eof())
            {
                std::cin >> app;
                project.observeApp(app);
            }
        }
        catch(...)
        {}
    }

    if( Config::get<bool>("ext4_only"))
        listener.watchExt4Only();

    CONNECT(&listener, eventParsed, boost::bind(&EventCatcher::handleAuditEvent, &project, _1));


    if(execute || 1 == getpid())
    {
        sem_t* sem = (sem_t*) mmap(NULL, sizeof (sem_t),
                                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (sem_init(sem, 1, 0) == -1)
        {
            error("sem_init: %s", strerror(errno));
            goto err2;
        }

        switch(fork())
        {
            case -1:
                error("Fork failed: %s", strerror(errno));
                break;
            case 0: //child process
                if(0 != prctl(PR_SET_PDEATHSIG, SIGINT))
                    error("Set parent death signal: %s", strerror(errno));
                notice("Connecting to the audit socket ...");
                listener.connect();
                if(0 != sem_post(sem))
                    error("sem_post: %s", strerror(errno));
                break;
            default:
                if(0 != sem_wait(sem))
                    error("sem_wait: %s", strerror(errno));
                sem_destroy(sem);
                munmap(sem, sizeof(sem_t));
                if(execute)
                {
                    notice("Execute `%s' ...", execute);
                    system(execute);
                }
                else
                {
                    notice("Execute `%s' ...", Config::get<std::string>("init").c_str());
                    execv(Config::get<std::string>("init").c_str(), argv);
                }
                sleep(2);
                exit(0);
         }
    }
    else
        listener.connect();

    if(create_pid_late)
    {
        createPidFile(PID_FILE);
        sigaction(SIGALRM, &sa, NULL);
        alarm(Config::get<unsigned int>("timeout"));
    }
    notice("Start event processing ...");
    listener.start();

    filelist = project.getFileList();
    
    notice("%d files scanned.", filelist.size());

    if(filelist.empty())
        goto out;
    /*
     * dump file list
     */
    if(outPath && !outStream)
    {
        outStream = fopen(outPath, "w");
        if(NULL == outStream)
        {
            error("Cannot open output file: %s: %s", outPath, strerror(errno));
            goto err2;
        }
    }
    
    if(outStream != stdout)
        notice("Save file list to %s", outPath);

    BOOST_FOREACH(FilePtr f, filelist)
        fprintf(outStream, "%u %u %s\n", (__u32)f.getDevice(), (__u32)f.getInode(), f.getPath().string().c_str());
    fclose(outStream);
out:
    unlink(PID_FILE);
    exit(0);
err1:
    printUsage();
    exit(1);
err2:
    if(getpid() == 1)
         execv(Config::get<std::string>("init").c_str(), argv);
    unlink(PID_FILE);
    exit(1);
}
