#!/usr/bin/env python
from __future__ import print_function, absolute_import
import logging
import os, os.path
import sys, subprocess, threading, time

import tornado.web
from tornado.netutil import bind_unix_socket
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.log import enable_pretty_logging
from tornado.escape import json_decode
import tornado.options
import terminado

STATIC_DIR = os.path.join(os.path.dirname(terminado.__file__), "_static")
TEMPLATE_DIR = os.path.dirname(__file__)
USER = os.environ['USER']

# This is the port we'll start handing things out at
port_base = 2023
server_list = {}

def get_my_external_ip():
    global server_list
    while server_list['sophia']['ip'] == 'saba.us':
        try:
            server_list['sophia']['ip'] = subprocess.check_output("whereami").strip()
            logging.info("Found external IP to be " + server_list['sophia']['ip'])
        except subprocess.CalledProcessError:
            pass

def reset_server_list():
    global server_list, USER
    server_list = {
        'sophia': {
            'hostname': 'sophia',
            'port':22,
            'ip':'saba.us',
            'user':USER,
            'mosh_path':'/usr/bin/mosh-server',
            'direct':True,
            'socat_process':None,
        }
    }
    t = threading.Thread(target=get_my_external_ip)
    t.daemon = True
    t.start()

def kill_all_tunnels():
    """
    Sometimes we just need to kill all the tunnels that have come in ever, so we
    don't rely upon our list, we instead ask `lsof` to look for all processes
    that are listening on the first 100 ports of our port_base and kill 'em all.
    """
    lsof_cmd = "sudo lsof -i:%d-%d -P -n"%(port_base, port_base+100)
    try:
        lsof_output = subprocess.check_output(lsof_cmd.split())
    except subprocess.CalledProcessError:
        return []
    ssh_procs = list(set([l.split()[1] for l in lsof_output.split('\n')[1:] if l]))
    for p in ssh_procs:
        subprocess.call(["sudo", "kill", p])
    return ssh_procs

update_in_progress = threading.Lock()
def update_direct_connects():
    """
    Loop through all servers, checking whether we can connect to them directly.
    If we can, then spit out bash aliases that do so by default, instead of
    proxying through the webmux server.
    """
    global server_list, update_in_progress

    logging.info("Checking direct connects for %d tunnels"%(len(server_list)))
    with update_in_progress:
        names = server_list.keys()

        for name in names:
            s = server_list[name]
            if 'last_direct_try' not in s or s['last_direct_try'] + 60*60 < time.time():
                logging.info("  Probing %s for direct connection on port %d..."%(s['hostname'], s['port']))

                s['last_direct_try'] = time.time()
                ssh_cmd = "ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no %s@%s source ~/.bash_profile; echo $HOSTNAME"%(s['user'], s['ip'])
                try:
                    remote_name = subprocess.check_output(ssh_cmd.split()).strip()
                    if remote_name == name:
                        logging.info("    Probed %s successfully!"%(name))
                        s['direct'] = True
                    else:
                        logging.info("    Failure on %s, hostname was %s!"%(name, remote_name))
                        s['direct'] = False
                except subprocess.CalledProcessError:
                    logging.info("    Failure on %s, (ssh connection failure)"%(name))
                    s['direct'] = False


socat_check_in_progress = threading.Lock()
def check_socat_tunnel():
    """
    Ensures that our mosh-enabling socat tunnels are in place on the server
    """
    global server_list, socat_tunnels_lock

    logging.info("Checking socat tunnel health for %d tunnels"%(len(server_list)))
    with socat_check_in_progress:
        for name in server_list.keys():
            s = server_list[name]
            # Skip ourselves
            if s['port'] == 22:
                continue
        
            # Was this guy's process never started, or worse, died?
            if s['socat_process'] == None or s['socat_process'].poll() != None:
                logging.info("Starting socat process for %s on port %d"%(s['hostname'], s['port'] + 1000))
                server_list[name]['socat_process'] = subprocess.Popen([
                    'socat',
                    'udp4-recvfrom:%d,reuseaddr,fork'%(s['port'] + 1000),
                    'tcp:localhost:%d'%(s['port'] + 1000),
                ])

class WebmuxTermManager(terminado.NamedTermManager):
    """Share terminals between websockets connected to the same endpoint.
    """
    def __init__(self, max_terminals=None, **kwargs):
        super(WebmuxTermManager, self).__init__(**kwargs)

    def get_terminal(self, port_number):
        assert port_number is not None

        if port_number in self.terminals:
            return self.terminals[port_number]

        if self.max_terminals and len(self.terminals) >= self.max_terminals:
            raise MaxTerminalsReached(self.max_terminals)

        # Find server mapped to this port
        name = filter(lambda n: server_list[n]['port'] == int(port_number), server_list.keys())[0]
        s = server_list[name]

        # Create new terminal
        logging.info("Attempting to connect to: %s@%s:%d", s['user'], name, s['port'])
        self.shell_command = ["ssh", "-o", "UserKnownHostsFile /dev/null", "-o", "StrictHostKeyChecking no", "-p", port_number, s['user']+"@localhost"]
        term = self.new_terminal()
        term.term_name = port_number
        self.terminals[port_number] = term
        self.start_reading(term)
        return term

class IndexPageHandler(tornado.web.RequestHandler):
    """Render the index page"""
    def get(self):
        logging.info("Hit the index page")
        return self.render("index.html", static=self.static_url, server_list=server_list)

class RegistrationPageHandler(tornado.web.RequestHandler):
    """Return a port number for a hostname"""
    def post(self):
        try:
            data = json_decode(self.request.body)
        except:
            logging.warn("Couldn't decode JSON body \"%s\" from IP %s"%(self.request.body, self.request.headers.get('X-Real-Ip')))
            return

        # If this hostname does not already exist, then create it with sane defaults
        if not data['hostname'] in server_list:
            port_number = max([int(server_list[k]['port']) for k in server_list] + [port_base - 1]) + 1

            data['port'] = port_number
            data['socat_process'] = None
            data['direct'] = False
            logging.info("Mapping %s to port %d"%(data['hostname'], port_number))
        else:
            # If it does already exist, then update everything with the old server_list object's contents
            for k in server_list[data['hostname']]:
                if not k in data:
                    data[k] = server_list[data['hostname']][k]

        # Always update the 'ip', in case the machine has moved since registration
        data['ip'] = self.request.headers.get("X-Real-IP")

        server_list[data['hostname']] = data

        # Let's take this opportunity to update our direct connects and check
        # our socat tunnels.  We don't mind doing this le very often.
        t = threading.Thread(target=update_direct_connects)
        t.daemon = True
        t.start()
        t = threading.Thread(target=check_socat_tunnel)
        t.daemon = True
        t.start()
        self.write(str(data['port']))

class ResetPageHandler(tornado.web.RequestHandler):
    """Reset all SSH connections forwarding ports"""
    def get(self):
        ssh_procs = kill_all_tunnels()
        reset_server_list()

        logging.info("Killed %d live SSH tunnels"%(len(ssh_procs)))
        self.write("Killed %d live SSH tunnels"%(len(ssh_procs)))

class TerminalPageHandler(tornado.web.RequestHandler):
    def get_host(self, port_number):
        for hostname in server_list:
            if server_list[hostname]['port'] == port_number:
                return hostname
        return "host on port " + port_number

    """Render the /shell/[\d]+ pages"""
    def get(self, port_number):
        return self.render("term.html", static=self.static_url,
                           ws_url_path="/_websocket/"+port_number,
                           hostname=self.get_host(port_number))

class BashPageHandler(tornado.web.RequestHandler):
    """Render the /bash page"""
    def get(self):
        global server_list
        commands = "#webmuxbash\n"
        for name in server_list:
            s = server_list[name]

            build_command = lambda name, prog, target: "function %s() { title %s; tmux_escape %s %s \"$@\"; }\n"%(name, name, prog, target)

            # Add .mosh* commands if we've got a mosh_path:
            if len(s['mosh_path']) != 0:
                # Add .mosh.direct command
                prog = "mosh --server=\"%s\""%(s['mosh_path'])
                target = "%s@%s"%(s['user'], s['ip'])
                commands += build_command(name+".mosh.direct", prog, target)

                # Add .mosh.webmux command
                target = "--ssh='ssh -p %d' --bind=any --port=%d %s@webmux.e.ip.saba.us"%(s['port'], s['port'] + 1000, s['user'])
                commands += build_command(name+".mosh.webmux", prog, target)

            # Add .ssh.direct command
            prog = "ssh"
            target = "%s@%s"%(s['user'], s['ip'])
            commands += build_command(name+".ssh.direct", prog, target)

            # Add .ssh.webmux command
            target = "-p %d %s@webmux.e.ip.saba.us"%(s['port'], s['user'])
            commands += build_command(name+".ssh.webmux", prog, target)

            # Decide whether we should prefer direct or webmux:
            direction = "direct"
            if not s["direct"]:
                direction = "webmux"

            # Add shortcuts like "name.ssh" and "name.mosh" that default to direct/webmux
            for m in ["ssh", "mosh"]:
                commands += "function %s.%s() { %s.%s.%s $*; };\n"%(name, m, name, m, direction)
            # Add shortcuts like "name.direct" and "name.webmux" that default to ssh/mosh
            for m in ["direct", "webmux"]:
                commands += "function %s.%s() { %s.ssh.%s $*; };\n"%(name, m, name, m)

            # Decide whether we should prefer mosh or ssh
            method = "ssh"
            if len(s['mosh_path']) != 0:
                method = "mosh"
            commands += "function %s() { %s.%s $*; }\n"%(name, name, method)

        self.write(commands)



if __name__ == "__main__":
    # Parse things like --loglevel
    tornado.options.parse_command_line()

    term_manager = WebmuxTermManager(shell_command=["echo"], max_terminals=100)

    handlers = [
        (r"/", IndexPageHandler),
        (r"/bash", BashPageHandler),
        (r"/reset", ResetPageHandler),
        (r"/register", RegistrationPageHandler),
        (r"/_websocket/(\w+)", terminado.TermSocket, {'term_manager': term_manager}),
        (r"/shell/([\d]+)/?", TerminalPageHandler),
        (r"/webmux_static/(.*)", tornado.web.StaticFileHandler, {'path':os.path.join(TEMPLATE_DIR,"webmux_static")}),
    ]
    application = tornado.web.Application(handlers, static_path=STATIC_DIR,
                              template_path=TEMPLATE_DIR,
                              term_manager=term_manager)

    SOCKET_PATH = "/tmp/webmux.socket"
    socket = bind_unix_socket(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0777)
    server = HTTPServer(application)
    server.add_socket(socket)
    enable_pretty_logging()

    try:
        # If we restarted or something, then be sure to cause all tunnels to reconnect
        reset_server_list()
        ssh_procs = kill_all_tunnels()
        logging.info("Killed %d SSH tunnels"%(len(ssh_procs)))
        logging.info("All systems operational, commander")
        IOLoop.current().start()
    except KeyboardInterrupt:
        logging.info("\nShutting down due to SIGINT")
    finally:
        term_manager.shutdown()
        IOLoop.current().close()
