#!/usr/bin/env python2.4

import ldap, ldapurl, re, sre_constants
import os, sys, time
from optparse import OptionParser
from ConfigParser import ConfigParser, NoOptionError, NoSectionError

rel_dir = os.path.dirname(sys.argv[0])

baseDN = 'ou=initScripts,dc=example,dc=com'
username = '' # empty string is an anonymous bind
password = ''

def green(text):
    return '\033[1;32m' + text + '\033[0;39m'
def red(text):
    return '\033[1;31m' + text + '\033[0;39m'
def bold(text):
    return '\033[1;39m' + text + '\033[0;39m'

def dumpConfig():
    ldapconfig = open('/etc/ldap.conf', 'r')
    ldaphosts = []
    for line in ldapconfig:
        try:
            tokens = line.split()
            if tokens[0] == 'host':
                ldaphosts.extend(tokens[1:]) # could 'break' here if you'd like to assume there is no more 'host' lines
            if tokens[0] == 'url':
                for url in tokens[1:]:
                    ldap_url = ldapurl.LDAPUrl(url)
                    ldaphosts.append(ldap_url.hostport)
        except (IndexError, ValueError), e:
            pass
    ldapconfig.close()
    #print ldaphosts

    # connect
    for host in ldaphosts:
        #print 'Trying to connect to server %s' % host
        try:
            l = ldap.open(host)
            l.protocol_version = ldap.VERSION3
            id = l.simple_bind(username,password)
            break # leave loop by this point with a good connection
        except ldap.LDAPError, e:
            print 'ldap connection error with "%s": %s' % (host, e)
    if not l:
        print 'No connections to ldap, not performing cfg sync.'
        return
    
    #search
    curhost = os.uname()[1]
    try:
        configfile = open(rel_dir + os.sep + 'initScripts.cfg', 'w')
    except (OSError, IOError), e:
        print 'Problem opening config file "initScripts.cfg": (%d) %s\n' % (e.errno, e.strerror)
        return(1)
    configfile.write(';\n; This file was created by initScripts.py on %s\n;\n' % time.ctime())
    try:
        result_id = l.search(baseDN, ldap.SCOPE_SUBTREE, 'cn=*')
        result_type, result_data = l.result(result_id, all=1)
        for scriptentry in result_data:
            resultDN, config = scriptentry
            #print '\nFound: %s' % resultDN
            cn = config['cn'].pop()
            
            # rid ourselves of unwanted values
            del config['cn']
            del config['objectClass']
            
            # only process the entries that match our hostname
            hostmatch = False
            for host in config['scriptHost']:
                if host == '*': # compensate this non regex pattern
                    host = '.*'
                try:
                    if re.search(host, curhost):
                        #print 'Matched this host from pat "%s"' % host
                        hostmatch = True
                        break
                except sre_constants.error, e:
                    print 'Warning: scriptHost entry of "%s" is not a valid regex.' % host
            if not hostmatch:
                continue
    
            # Now actually print out the entries in configParser style
            configfile.write('[%s]\n' % cn)
            for key, values in config.iteritems():
                #print 'KEY %s = %s' % (key,values)
                configfile.write('%s=%s\n' % (key,values.pop()))
                for extravalue in values:
                    configfile.write('  %s\n' % extravalue)
            configfile.write('\n')
    except ldap.LDAPError, e:
        print e

def start(initDict):
    print 'Starting %s' % bold(initDict['name'])
    try:
        os.stat(initDict['startprogram'].split()[0])
    except (OSError,KeyError), e:
        print 'Start Error: %s' % e
        return False
    command = '/bin/su - %s -c "%s"' % (initDict['user'], initDict['startprogram'])
    rc = os.system(command)
    return (rc == 0)
def stop(initDict):
    print 'Stopping %s' % bold(initDict['name'])
    try:
        os.stat(initDict['stopprogram'].split()[0])
    except (OSError,KeyError), e:
        print 'Start Error: %s' % e
        return False
    command = '/bin/su - %s -c "%s"' % (initDict['user'], initDict['stopprogram'])
    rc = os.system(command)
    return (rc == 0)
def restart(initDict):
    stop(initDict)
    return start(initDict)
def condstart(initDict):
    if statussummary(initDict):
        print '%s is already running.' % bold(initDict['name'])
        return True
    else:
        print '%s is not running. Calling start.' % bold(initDict['name'])
        return (start(initDict))
def status(initDict):
    try:
        for pidfile in initDict['pidfile'].split('\n'):
            print 'Checking process from pidfile "%s"' % pidfile
            f = open(pidfile,'r')
            pid = int(f.readline())
            try:
                os.kill(pid, 0)
            except OSError, e:
                print 'process %d (from pidfile "%s") not running' % (pid, pidfile)
                return False
            f.close()
        return True
    except (KeyError,IOError), e:
        print 'Error using pidfiles; Using monitor program for status'
    # only here if we had an issue using the pidfiles (or didn't exist)
    try:
        command = '/bin/su - %s -c "%s"' % (initDict['user'], initDict['monitorprogram'])
        #print command
        rc = os.system(command)
        return (rc == 0)
    except KeyError, e:
        print 'Error using the monitor program to ascertain a status'
        return False
def statussummary(initDict):
    try:
        for pidfile in initDict['pidfile'].split('\n'):
            f = open(pidfile,'r')
            pid = int(f.readline())
            try:
                os.kill(pid, 0)
            except OSError, e:
                return False
            f.close()
        return True
    except (KeyError,IOError), e:
        pass
    # only here if we had an issue using the pidfiles (or didn't exist)
    try:
        command = '/bin/su - %s -c "%s" 1>/dev/null 2>/dev/null' % (initDict['user'], initDict['monitorprogram'])
        rc = os.system(command)
        return (rc == 0)
    except KeyError, e:
        return False
def clean(initDict):
    print 'Cleaning %s' % bold(initDict['name'])
    try:
        os.stat(initDict['cleanprogram'].split()[0])
    except (OSError,KeyError), e:
        print 'Start Error: %s' % e
        return False
    command = '/bin/su - %s -c "%s"' % (initDict['user'], initDict['cleanprogram'])
    rc = os.system(command)
    return (rc == 0)

#----------------------------------------------------------------------
if __name__ == '__main__':

    usage = '%prog [-y] start|stop|status|restart|condstart|statussummary|clean [name]'
    parser = OptionParser(usage, version="initScripts 1.2")
    parser.add_option("-y", "--yes",
                      action="store_true", dest="theanswerisyes", default=False,
                      help="answer yes to all questions")

    (options, args) = parser.parse_args()
    if len(args) == 0:
        parser.error('incorrect number of arguments')
        sys.exit(1)
        
    # various modes this script will run under
    modes = {'start': start, 'stop': stop, 'restart': restart, 'condstart': condstart,
             'status': status, 'statussummary': statussummary, 'clean': clean, 'monitor': statussummary }
    if not modes.has_key(args[0]):
        parser.error('Invalid option of "%s" specified.' % args[0])
        sys.exit(2)
    mode = args[0]

    try:
        initName = args[1]
    except IndexError, e:
        initName = ''
    if ((not options.theanswerisyes) and (mode != 'status' and mode != 'statussummary' and mode != 'monitor') and not initName):
        # get confirmation from user that they *know* what they're doing.
        ans = raw_input('Are you sure you want to %s each configured application on this box?(y/n) ' % mode)
        if ans[0:] == 'y':
            options.theanswerisyes = True
        else:
            print 'Nice choice. If you\'d like to be more cautious then perhaps you should use the "status" option first and/or read the usage statement via the "--help" option.'
            print 'Till we meet again.'
            sys.exit(0)

    # attempt to grab an updated config from LDAP
    dumpConfig()

    try:
        pipeCmd = os.popen('/sbin/runlevel')
        curRunlevel = pipeCmd.readline().split(' ')[1].strip()
        #print 'Current runlevel is %s' % curRunlevel
        pipeCmd.close()
    except Exception, e:
        print 'Can not ascertain current runlevel: %s ' % e
        sys.exit(3)

    # parse the config
    try:
        configfile = open(rel_dir + os.sep + 'initScripts.cfg', 'r')
    except (OSError, IOError), e:
        print 'Problem opening config file "initScripts.cfg": (%d) %s\n' % (e.errno, e.strerror)
        sys.exit(4)
    config = ConfigParser()
    config.readfp(configfile)
    orderScripts = {}
    for section in config.sections():
        if initName and section != initName:
            continue
        initDict = {}
        initDict['name'] = section
        try:
            for name, value in config.items(section):
                #print('  %s => %s' % (str(name),repr(value)))
                initDict[name] = value
                
        except (ImportError, NoOptionError):
            print('Could not service section "%s"; Verify "plugin" value.' % section)
            continue

        # Apply some filters
        if not curRunlevel in initDict['runlevel'].split('\n'):
            print 'Discarding %s because it is not configured to run in current runlevel of %s' % (bold(initDict['name']), curRunlevel)
            continue

        # in order to respect the OrderNumber I need to sort after processing all initscripts data
        numKey = int(initDict['ordernumber'])
        if not orderScripts.has_key(numKey):
            orderScripts[numKey] = []
        orderScripts[numKey].append(initDict)

    # call the mode for each script, in order.
    allNumbers = orderScripts.keys()
    allNumbers.sort()
    for N in allNumbers: # ala S87 = 87, S99 = 99, etc
        for initDict in orderScripts[N]: # ala S87myapp1 = myapp1[], S99myapp2 = myapp2[], etc
            #call the specified routine
            if mode == 'monitor':
                if not modes[mode](initDict):
                    #print 'Error: Application "%s" is not running. Verify via "sudo /etc/init.d/initScripts.py status"' % initDict['name']
                    print 'Error: Application "%s" is not running.' % initDict['name'].replace('_','')
                    #getanswers_identifier = ''
                    #for c in initDict['name']:
                        #getanswers_identifier += str(hex(ord((c))))[2:]
                    #print 'Error %s: Application "%s" is not running.' % (getanswers_identifier, initDict['name'])
            else:
                if modes[mode](initDict):
                    print 'Calling %s for %s \033[60G[%s]' % (mode,bold(initDict['name']),green('OK'))
                else:
                    print 'Calling %s for %s \033[60G[%s]' % (mode,bold(initDict['name']),red('FAILURE'))
