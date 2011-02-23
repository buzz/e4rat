/*
 * listener.cc - Listen to the Linux audit socket
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
#include "logging.hh"
#include "device.hh"

#include <libaudit.h>
#include <auparse.h>
#include <auparse-defs.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <linux/limits.h>
#include <fcntl.h>

//syscall table
#include <linux/unistd.h>
//mount flags
#include <linux/fs.h>
#include <sys/vfs.h>

#include <boost/foreach.hpp>

AuditEvent::AuditEvent()
{
    ino = 0;
    dev = 0;
    readOnly = false;
    successful = false;
}

AuditListener::AuditListener()
{
    memset(&auditRuleData, 0, sizeof(struct audit_rule_data));
    auditFlags = AUDIT_FILTER_EXIT;
    auditAction = AUDIT_ALWAYS;
    audit_fd = -1;
    ext4_only = false;
}

AuditListener::~AuditListener()
{
}

void AuditListener::excludePath(std::string path)
{
    exclude_paths.push_back(
    path2regex(realpath(path).string()));
}

void AuditListener::watchPath(std::string path)
{
    if(path == "/")
        // does not make sense
        // and leads to unwanted behaviour
        return;
    
    watch_paths.push_back(
    path2regex(realpath(path).string()));
}

void AuditListener::excludeDevice(std::string wildcard)
{
    struct stat st;
    BOOST_FOREACH(std::string d, matchPath(wildcard))
    {
        if( 0 > stat(d.c_str(), &st))
            continue;
        exclude_devices.insert(st.st_rdev);
    }
}

void AuditListener::watchDevice(std::string wildcard)
{
    struct stat st;
    BOOST_FOREACH(std::string d, matchPath(wildcard))
    {
        if( 0 > stat(d.c_str(), &st))
            continue;
        watch_devices.insert(st.st_rdev);
    }
}

void AuditListener::watchExt4Only(bool v)
{
    ext4_only = v;
}

void AuditListener::watchFileSystemType(long t)
{
    watch_fs_types.insert(t);
}

/* Rule flags - Rules can be applied to following filter set.
 *   AUDIT_FILTER_USER       0x00     Apply rule to user-generated messages 
 *   AUDIT_FILTER_TASK       0x01     Apply rule at task creation (not syscall) 
 *   AUDIT_FILTER_ENTRY      0x02     Apply rule at syscall entry 
 *   AUDIT_FILTER_WATCH      0x03     Apply rule to file system watches 
 *   AUDIT_FILTER_EXIT       0x04     Apply rule at syscall exit 
 *   AUDIT_FILTER_TYPE       0x05     Apply rule at audit_log_start
 * 
 * Action is either never or always
 */
void AuditListener::insertAuditRules()
{
    int action = AUDIT_ALWAYS;

    if(audit_fd < 0)
    {
        audit_fd = audit_open();
        if (-1 == audit_fd)
            error("Cannot open audit socket");
    }
    else
        removeAuditRules();

    memset(&auditRuleData, '\0', sizeof(struct audit_rule_data));

    audit_rule_syscallbyname_data(&auditRuleData, "execve");
    audit_rule_syscallbyname_data(&auditRuleData, "open");
    audit_rule_syscallbyname_data(&auditRuleData, "openat");
    audit_rule_syscallbyname_data(&auditRuleData, "truncate");
#ifdef __i386__
    audit_rule_syscallbyname_data(&auditRuleData, "truncate64");
#endif
    audit_rule_syscallbyname_data(&auditRuleData, "creat"); 

    if ( 0 >= audit_add_rule_data(audit_fd, &auditRuleData, AUDIT_FILTER_EXIT, action))
        error("Cannot insert rules: %s", strerror(errno));

    if(0 > audit_set_pid(audit_fd, getpid(), WAIT_YES))
        error("Cannot set pid to audit");

    //set 1 to enable auditing
    //set 2 to enable auditing and lock the configuration
    if(0 > audit_set_enabled(audit_fd, 1))
        error("Cannot enable audit");

    if(0 > audit_set_backlog_limit(audit_fd, 256))
        audit_request_status(audit_fd);
}

void AuditListener::removeAuditRules()
{
    if (audit_fd < 0)
        return;

    if ( 0 > audit_delete_rule_data(audit_fd,
                                    &auditRuleData,
                                    AUDIT_FILTER_EXIT,
                                    AUDIT_ALWAYS))
    {
        debug("Cannot remove rules: %s", strerror(errno));
    }
}

void AuditListener::closeAuditSocket()
{
    removeAuditRules();
    
    if(0 > audit_set_enabled(audit_fd, 0))
        error("Cannot disable audit socket");

    if(0 > audit_set_pid(audit_fd, 0, WAIT_NO))
        error("Cannot disable current pid");

    audit_close(audit_fd);
    audit_fd = -1;
}

/*
 * parse value of an audit event name=value
 */
inline std::string AuditListener::parseField(auparse_state_t* au, const char* name)
{
    if(0 == auparse_find_field(au, name))
        return std::string();
    
    return std::string(auparse_get_field_str(au));
}

/*
 * parse path value of an audit event name="path"
 */
inline std::string AuditListener::parsePathField(auparse_state_t* au, const char* name)
{
    
    std::string buf(parseField(au, name));
    if(buf.empty())
        return buf;
    
    buf = buf.substr(1, buf.size() -2);

    //auparse has a bug that's why it reads sometimes too far
    size_t found = buf.find_first_of("\"");
    if(found != buf.npos)
        buf.resize(found);

    if(buf == "null")
        buf.clear();

    return buf;
}

/*
 * Listen to the audit socket. 
 * The Function hangs on until it received an event or user interrupt.
 */
void AuditListener::waitForEvent(struct audit_reply* reply)
{
    fd_set read_mask;
    struct timeval tv;
    int    retval;
    
repeat:
    do {
        // TODO: very slow due quitting. 
        // need opportunity to awake while sleeping
        interruptionPoint();
        
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        FD_ZERO(&read_mask);
        FD_SET(audit_fd, &read_mask);
        
        retval = select(audit_fd+1, &read_mask, NULL, NULL, &tv);
        
    } while (retval == -1 && errno == EINTR);

    retval = audit_get_reply(audit_fd, reply,
                             GET_REPLY_NONBLOCKING, 0);
    if(0 > retval){
        goto repeat;
    }
}

/*
 * Initialize the auparse state object.
 * Ignore invalid events
 *
 * Return NULL on error
 */
auparse_state_t* AuditListener::initAuParse(struct audit_reply* reply)
{
    auparse_state_t *au;
    std::string parse_str;

    // prepend a message type header in order to use the auparse library functions
    if(reply->type == AUDIT_PATH)
        parse_str = "type=PATH msg=";
    else if(reply->type == AUDIT_CWD)
        parse_str = "type=CWD msg=";
    else
        parse_str = "type=UNKNOWN msg=";

    parse_str += reply->msg.data;
    parse_str += "\n";

    au = auparse_init(AUSOURCE_BUFFER, parse_str.c_str());
    if(au == NULL)
        error("cannot init auparse");
    
    if (-1 == auparse_next_event(au))
        error("auparse_next_event: %s", strerror(errno));
    return au;
}

/*
 * Parse Field cwd="current working directory"
 */
void AuditListener::parseCwdEvent(auparse_state_t* au, boost::shared_ptr<AuditEvent> auditEvent)
{
    auditEvent->cwd = parsePathField(au, "cwd");
}

/*
 * Parse path="filename" field. 
 * It is filename the syscall event refers to.
 */
void AuditListener::parsePathEvent(auparse_state_t* au, boost::shared_ptr<AuditEvent> auditEvent)   
{
    auditEvent->path = realpath(parsePathField(au, "name"),
                                auditEvent->cwd);
    auditEvent->ino = atoll(parseField(au, "inode").c_str());
    
    std::string dev_buf = parseField(au, "dev");
    size_t found = dev_buf.find(":");
    if(found == std::string::npos)
        auditEvent->dev = 0;
    else
        auditEvent->dev = makedev(strtol(dev_buf.substr(0, found).c_str(), NULL, 16),
                                  strtol(dev_buf.substr(found+1).c_str(),NULL, 16));
}

/*
 * Main entry point of parsing syscall audit event
 */
void AuditListener::parseSyscallEvent(auparse_state_t* au, boost::shared_ptr<AuditEvent> auditEvent)
{
    int syscall;
    
    //notice: you have to read audit message items in the correct order
    syscall = strtol(parseField(au, "syscall").c_str(), NULL, 10);
    switch(syscall)
    {
        case __NR_open:                        
            auditEvent->type = Open;     break;
        case __NR_execve:
            auditEvent->type = Execve;   break;
        case __NR_openat:
            auditEvent->type = OpenAt;   break;
        case __NR_truncate:
#ifdef __i386__
        case __NR_truncate64:
#endif
            auditEvent->type = Truncate; break;
        case __NR_creat:
            auditEvent->type = Creat;   break;          
        default:
            debug("unknown syscall: %d", syscall);
    }
    
    if("yes" == parseField(au, "success"))
        auditEvent->successful = true;
    
    
    if(auditEvent->type == Open || auditEvent->type == OpenAt)
    {
        int flags = strtol(parseField(au, "a1").c_str(), NULL, 16);
        
        if(!(  flags & O_WRONLY
            || flags & O_RDWR
            || flags & O_CREAT))
            auditEvent->readOnly = true;
    }
    
    auditEvent->ppid = strtoll(parseField(au, "ppid").c_str(), NULL, 10);
    auditEvent->pid  = strtoll(parseField(au, "pid" ).c_str(), NULL, 10);
    auditEvent->comm = parsePathField(au, "comm");
    auditEvent->exe  = parsePathField(au, "exe");
}

/*
 * test whether path does match regex
 * return true either on exactly match
 *                 or regex represents a subdirectory of path
 *        otherwise false
 */
bool doesRegexMatchPath(fs::path& p, boost::regex& filter)
{
    boost::match_results<std::string::const_iterator> what;
    if( boost::regex_search(p.string(), what, filter, 
                            boost::match_default | boost::match_continuous  ))
    {
        //partial match beginning at first character found
        size_t match_end =  distance(what[0].first, what[0].second);
        
        //test for exact match
        if(match_end >= p.string().size())
            return true;
        //test whether partial path match points to a directory
        if('/' == p.string().at(match_end))
            return true;
        
    }
    return false;
}

/*
 * Test whether file is excluded by an path regex
 * Return true path is ignored
 *        otherwise false
 */
bool AuditListener::ignorePath(fs::path& p)
{
    if(!watch_paths.empty())
    {
        BOOST_FOREACH(boost::regex filter, watch_paths)
            if(doesRegexMatchPath(p,filter))
                goto path_valid;

        return true;
    }
path_valid:
    BOOST_FOREACH(boost::regex filter, exclude_paths)
        if(doesRegexMatchPath(p, filter))
            return true;
    
    return false;
}


/*
 * Test whether file is excluded by its device id
 */
bool AuditListener::ignoreDevice(dev_t dev)
{
    if(exclude_devices.end() != exclude_devices.find(dev))
        return true;

    if(!watch_devices.empty())
        if(watch_devices.end() != watch_devices.find(dev))
            return false;

    if(ext4_only)
    {
        Device device(dev);
        if(device.getFileSystem() == "ext4")
            watch_devices.insert(dev);
        else
        {
            std::string dev_name = device.getDevicePath();
            if(dev_name.at(0) != '/') //it's virtual fs: display mount point instead of cunfusing device name.
                dev_name = device.getMountPoint().string();
            info("%s is not an ext4 filesystem", dev_name.c_str());
            info("Filesystem of %s is %s", dev_name.c_str(), device.getFileSystem().c_str());
            exclude_devices.insert(dev);
            return true;
        }
    }
    return false;
}

/*
 * Check if filesystem type is ignored
 */
bool AuditListener::checkFileSystemType(fs::path& p)
{
    struct statfs fs;
    if(0 > statfs(p.string().c_str(), &fs))
        return false;

    if(!watch_fs_types.empty())
    {
        if(watch_fs_types.end() == watch_fs_types.find(fs.f_type))
            return false;
    }
    return true;
}

/*
 * Infinite loop of listening to the Linux audit system
 */
void AuditListener::exec()
{
    struct audit_reply reply;
    auparse_state_t *au;
    boost::shared_ptr<AuditEvent> auditEvent(new AuditEvent);

    while(1)
    {
        waitForEvent(&reply);

        reply.msg.data[reply.len] = '\0';
        au = initAuParse(&reply);
        debug("%d: %*s", reply.type, reply.len, reply.msg.data);
        
        switch(reply.type)
        {
            // change working directory
            case AUDIT_CWD:
                parseCwdEvent(au, auditEvent);
                break;
            // event refers to file
            case AUDIT_PATH:
                parsePathEvent(au,auditEvent);

                if(!auditEvent->successful)
                    break;
                if(auditEvent->path.empty())
                    break;

                if(!ignorePath(auditEvent->path)
                   && !ignoreDevice(auditEvent->dev)
                   && checkFileSystemType(auditEvent->path))
                    eventParsed(auditEvent);

                break;
            // event is an syscall event
            case AUDIT_SYSCALL:
                parseSyscallEvent(au,auditEvent);
                break;
            // end of multi record event
            case AUDIT_EOE:
                auditEvent = boost::shared_ptr<AuditEvent>(new AuditEvent);
                break;
            default:
                break;
        }
        auparse_destroy(au);
    }
}


Listener::~Listener()
{}

void Listener::stop()
{
    InterruptAble::interrupt();
}

void Listener::connect()
{
    insertAuditRules();
}

void Listener::start()
{
    try{
        exec();
    }
    catch(UserInterrupt&)
    {}
    removeAuditRules();
    closeAuditSocket();
}
