/*
 * listener.hh - Listen to the Linux audit socket
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

#ifndef LISTENER_HH
#define LISTENER_HH

#include "common.hh"
#include "signals.hh"

#include <set>
#include <sys/stat.h>
#include <libaudit.h>

typedef struct opaque auparse_state_t;

// All known events emitted by AuditListener
enum AuditEventType
{
    Open,
    OpenAt,
    Execve,
    Truncate,
    Creat,
};

// AuditEvent is an structure emitted by eventParsed() signal.
class AuditEvent
{
    public:
        AuditEvent();
        AuditEventType type;
        pid_t pid;
        pid_t ppid;
        std::string comm;
        fs::path exe;
        fs::path path;
        fs::path cwd;
        ino_t ino;
        dev_t dev;
        bool readOnly;
        bool successful;
};


/*
 * Linux Audit Listener Class
 * It directly connects to the Linux audit socket.
 *
 * For each successfully parsed event signal eventParsed() is emitted.
 *
 * Derivate this class to implement interuptionPoint() method
 * which differ in single and multi-threaded applications.
 */
class AuditListener : public InterruptAble
{
        SIGNAL(eventParsed, boost::shared_ptr<AuditEvent>);

    public:
        AuditListener();
        ~AuditListener();
        void excludePath(std::string);
        void watchPath(std::string);
        void watchFileSystemType(long);
        void excludeDevice(std::string);
        void watchDevice(std::string);
        void watchExt4Only(bool = true);
    protected:
        virtual void exec();
        void insertAuditRules();
        void removeAuditRules();
        void closeAuditSocket();        
        std::string parseField(auparse_state_t*, const char*);
        std::string parsePathField(auparse_state_t*, const char*);
    private:
        void waitForEvent(struct audit_reply* reply);
        auparse_state_t* initAuParse(struct audit_reply*);
        void parseCwdEvent(auparse_state_t*, boost::shared_ptr<AuditEvent>);
        void parsePathEvent(auparse_state_t*, boost::shared_ptr<AuditEvent>);
        void parseSyscallEvent(auparse_state_t*, boost::shared_ptr<AuditEvent>);
        bool ignorePath(fs::path&);
        bool ignoreDevice(dev_t dev);
        bool checkFileSystemType(fs::path& p);

        struct audit_rule_data* auditRuleData;
        int auditFlags;
        int auditAction;                
        int audit_fd;
        std::vector<boost::regex> exclude_paths;
        std::vector<boost::regex> watch_paths;
        std::set<dev_t> watch_devices;
        std::set<dev_t> exclude_devices;
        std::set<long>  watch_fs_types;
        bool ext4_only;
};

/*
 * Single threaded Linux Audit Listener
 */
class Listener : public AuditListener
{
    public:
        virtual ~Listener();
        void connect();
        void start();
        void stop();
};

#endif
