#!/usr/bin/env python
from __future__ import print_function, absolute_import
import logging
import os, os.path
import sys, subprocess, threading, time
import requests, re

import tornado.web
from tornado.netutil import bind_unix_socket
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.log import enable_pretty_logging
from tornado.escape import json_decode
import tornado.options
import terminado
import traceback

STATIC_DIR = os.path.join(os.path.dirname(terminado.__file__), "_static")
TEMPLATE_DIR = os.path.dirname(__file__)

# This is the port we'll start handing things out at
port_base = 2023
server_list = {}

def get_my_external_ip():
    global server_list
    while server_list['sophia']['host_ip'] == 'saba.us':
        try:
            findTags = re.compile(r'<.*?>')
            findIP = re.compile(r'\d+\.\d+\.\d+\.\d+')

            html = requests.get('http://checkip.dyndns.org' ).text()
            ipaddress = findIP.search(findTags.sub('', html))
            if ipaddress is not None:
                server_list['sophia']['host_ip'] = ipaddress.group(0)
                logging.info("Found external IP to be %s"%(server_list['sophia']['host_ip']))
        except:
            pass

def reset_server_list():
    global server_list
    server_list = {
        'sophia': {
            'hostname': 'sophia',
            'host_port': 22,
            'webmux_port': 22,
            'host_ip': 'saba.us',
            'user': 'sabae',
            'mosh_path': '/usr/bin/mosh-server',
            'direct': True,
            'socat_process': None,
            'last_direct_try': 1e100,
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
    lsof_cmd = "lsof -i:%d-%d -P -n"%(port_base, port_base+100)
    try:
        lsof_output = subprocess.check_output(lsof_cmd.split())
    except subprocess.CalledProcessError:
        return []
    except:
        traceback.print_exc(file=sys.stdout)
        logging.warning("Unable to probe active tunnels")
        return []
    
    ssh_procs = list(set([l.split()[1] for l in lsof_output.split('\n')[1:] if l]))
    for p in ssh_procs:
        subprocess.call(["kill", p])

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
        names = [k for k in server_list.keys()]

        for name in names:
            s = server_list[name]
            if s['last_direct_try'] + 60*60 < time.time():
                s['last_direct_try'] = time.time()
                logging.info("  Probing %s for direct connection on port %d..."%(name, s['host_port']))

                try:
                    finger_cmd = ["ssh-keyscan", "-H", "-p", str(s['host_port']), s['host_ip']]
                    fingerprints = subprocess.check_output(finger_cmd, stderr=subprocess.DEVNULL)
                    fingerprints = [f.strip().split() for f in fingerprints.decode('utf-8').split('\n')]
                    fingerprints = [f[2] for f in fingerprints if f and len(f) >= 3]
                    if any(f == s['fingerprint'] for f in fingerprints):
                        logging.info("    Probed %s successfully!"%(name))
                        s['direct'] = True
                    else:
                        logging.info("    Probe failure on %s, fingerprint mismatch!"%(name))
                        s['direct'] = False
                except subprocess.CalledProcessError as e:
                    logging.info(e)
                    logging.info("    Probe failure on %s, (ssh connection failure)"%(name))
                    s['direct'] = False


socat_check_in_progress = threading.Lock()
def check_socat_tunnel():
    """
    Ensures that our mosh-enabling socat tunnels are in place on the server
    """
    global server_list

    logging.info("Checking socat tunnel health for %d tunnels"%(len(server_list)))
    with socat_check_in_progress:
        for name in [k for k in server_list.keys()]:
            s = server_list[name]
            # Skip ourselves
            if s['webmux_port'] == 22:
                continue
        
            # Was this guy's process never started, or worse, died?
            if s['socat_process'] == None or s['socat_process'].poll() != None:
                logging.info("Starting socat process for %s on port %d"%(s['hostname'], s['webmux_port'] + 1000))
                server_list[name]['socat_process'] = subprocess.Popen([
                    'socat',
                    'udp4-recvfrom:%d,reuseaddr,fork'%(s['webmux_port'] + 1000),
                    'tcp:localhost:%d'%(s['webmux_port'] + 1000),
                ], stderr=subprocess.DEVNULL)

class WebmuxTermManager(terminado.NamedTermManager):
    """Share terminals between websockets connected to the same endpoint.
    """
    def __init__(self, max_terminals=None, **kwargs):
        super(WebmuxTermManager, self).__init__(**kwargs)

    def get_terminal(self, port_number):
        from terminado.management import MaxTerminalsReached

        # This is important lel
        assert port_number is not None

        if port_number in self.terminals:
            return self.terminals[port_number]

        if self.max_terminals and len(self.terminals) >= self.max_terminals:
            raise MaxTerminalsReached(self.max_terminals)

        # Find server mapped to this port
        name = next(filter(lambda n: server_list[n]['webmux_port'] == int(port_number), server_list.keys()))
        s = server_list[name]

        # Create new terminal
        logging.info("Attempting to connect to: %s@%s:%d", s['user'], name, s['webmux_port'])
        self.shell_command = ["ssh", "-o", "UserKnownHostsFile /dev/null", "-o", "StrictHostKeyChecking no", "-p", port_number, s['user']+"@webmux.e.ip.saba.us"]
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
        
        # Always update the 'host_ip'
        data['host_ip'] = self.request.headers.get("X-Real-IP")

        # Convert `host_port` to an integer
        data['host_port'] = int(data['host_port'])

        # If this hostname does not already exist in server_list, then initialize some sane defaults for `data`
        # before we put it into `server_list`.
        if not data['hostname'] in server_list:
            port_number = max([server_list[k]['webmux_port'] for k in server_list] + [port_base - 1]) + 1

            data['webmux_port'] = port_number
            data['socat_process'] = None
            data['direct'] = False
            data['last_direct_try'] = 0

            server_list[data['hostname']] = data
        else:
            # Otherwise update server_list with the given data
            server_list[data['hostname']].update(data)
            data = server_list[data['hostname']]

        # Log out a little bit
        logging.info("Registered %s at %s:%d on webmux port %d"%(data['hostname'], data['host_ip'], data['host_port'], data['webmux_port']))

        # Let's take this opportunity to update our direct connects and check
        # our socat tunnels.  We don't mind doing this very often.
        t = threading.Thread(target=update_direct_connects)
        t.daemon = True
        t.start()
        t = threading.Thread(target=check_socat_tunnel)
        t.daemon = True
        t.start()
        self.write(str(data['webmux_port']))

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
            if server_list[hostname]['webmux_port'] == port_number:
                return hostname
        return "host on port " + port_number

    """Render the /shell/[\\d]+ pages"""
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

            build_command = lambda name, prog: "function %s() { title %s; tmux_escape %s \"$@\"; title; }\n"%(name, name, prog)
            ssh_cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "

            # Add .mosh* commands if we've got a mosh_path:
            if len(s['mosh_path']) != 0:
                # Add .mosh.direct command
                prog_base = "mosh --server=\"%s\" --bind=any "%(s['mosh_path'])
                prog = prog_base + "--ssh='%s -p %d' %s@%s"%(ssh_cmd, s['host_port'], s['user'], s['host_ip'])
                commands += build_command(name+".mosh.direct", prog)

                # Add .mosh.webmux command
                prog = prog_base + "--ssh='%s -p %d' --port=%d %s@webmux.e.ip.saba.us"%(ssh_cmd, s['webmux_port'], s['webmux_port'] + 1000, s['user'])
                commands += build_command(name+".mosh.webmux", prog)

            # Add .ssh.direct command
            prog = ssh_cmd + "-p %d %s@%s"%(s['host_port'], s['user'], s['host_ip'])
            commands += build_command(name+".ssh.direct", prog)

            # Add .ssh.webmux command
            prog = ssh_cmd + "-p %d %s@webmux.e.ip.saba.us"%(s['webmux_port'], s['user'])
            commands += build_command(name+".ssh.webmux", prog)

            # Decide whether we should prefer direct or webmux:
            direction = "direct"
            if not s["direct"]:
                direction = "webmux"
            
            # Decide whether we should prefer mosh or ssh
            prefer_prog = "ssh"
            if len(s['mosh_path']) != 0:
                prefer_prog = "mosh"

            # Start with the big kahuna; `mieli` will sub out to `mieli.ssh` or `mieli.mosh` first:
            if prefer_prog == "mosh":
                # If we prefer mosh for this target, check if the connecting host
                # even has `mosh` available, and if so, try to use it.  :)
                commands += """
                function %s() {
                    if [[ -n $(which mosh 2>/dev/null) ]]; then
                        %s.mosh $*;
                    else
                        %s.ssh $*;
                    fi;
                }
                """%(name, name, name)
            else:
                # If we don't prefer mosh, just jump straight to `ssh`.
                commands += """
                function %s() {
                    %s.ssh $*;
                }
                """%(name, name)

            # Next, add shortcust like "name.ssh" and "name.mosh" that default to direct/webmux
            for prog in ["ssh", "mosh"]:
                commands += """
                function %s.%s() {
                    %s.%s.%s $*;
                };"""%(name, prog, name, prog, direction)

            # Finally, add shortcust like "name.direct" and "name.webmux" that default to ssh/mosh
            for direction in ["direct", "webmux"]:
                commands += """
                function %s.%s() {
                    %s.%s.%s $*;
                };"""%(name, direction, name, prefer_prog, direction)
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
                              term_manager=term_manager, debug=True)
    application.listen(8888)

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
