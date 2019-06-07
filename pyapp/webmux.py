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

def get_external_ip():
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

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    return s.getsockname()[0]

def reset_server_list():
    global server_list
    server_list = {
        'sophia': {
            'hostname': 'sophia',
            'host_port': 22,
            'webmux_port': 22,
            'global_ip': 'saba.us',
            'local_ip': get_local_ip(),
            'user': 'sabae',
            'direct': True,
            'last_direct_try': 1e100,
        }
    }
    t = threading.Thread(target=get_global_ip)
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
            data['direct'] = False
            data['last_direct_try'] = 0

            server_list[data['hostname']] = data
        else:
            # Otherwise update server_list with the given data
            server_list[data['hostname']].update(data)
            data = server_list[data['hostname']]

        # Log out a little bit
        logging.info("Registered %s at %s:%d on webmux port %d"%(data['hostname'], data['host_ip'], data['host_port'], data['webmux_port']))
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

        # Add some helpful tools at the beginning
        commands += """
        GLOBAL_IP = $(curl -s http://whatismyip.akamai.com)

        # Helper function to see if we're on the same global subnet or not,
        # (just checks if the X's are the same in X.X.X.Z, this is good enough
        # 99% of the time)
        same_global_subnet() { [[ ${GLOBAL_IP%.*} == ${1%.*} ]]; }

        # Check if an interface is "up"
        if_up()
        {
            if [[ $(uname 2>/dev/null) == "Darwin" ]]; then
                [[ -n $(ifconfig "$1" 2>/dev/null | grep -e "flags=.*UP[,>]") ]]
            else
                [[ -n $(ip address show "$1" up 2>/dev/null) ]]
            fi
        }

        wireguard_up() { [[ -n $(if_up $(wg show interfaces 2>/dev/null)) ]]; }
        """
        for name in server_list:
            s = server_list[name]

            build_command = lambda name, prog: "function %s() { title %s; tmux_escape %s \"$@\"; title; }\n"%(name, name, prog)
            ssh_cmd = "ssh -A -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "

            # Add .global for connecting to global host IP directly
            prog = ssh_cmd + "-p %d %s@%s"%(s['host_port'], s['user'], s['host_ip'])
            commands += build_command(name+".global", prog)

            # Add .local for connecting to local host IP directly
            prog = ssh_cmd + "-p %d %s@%s"%(s['host_port'], s['user'], s['local_ip'])
            commands += build_command(name+".local", prog)

            # Add .webmux command for connecting to webmux reverse-tunnel
            prog = ssh_cmd + "-p %d %s@webmux.e.ip.saba.us"%(s['webmux_port'], s['user'])
            commands += build_command(name+".webmux", prog)

            # Add .sabanet command for connecting over wireguard
            prog = ssh_cmd + "-p %d %s@%s"%(s['host_port'], s['user'], sabanetify(name))
            commands += build_command(name+".sabanet", prog)

            commands += """
            function %s() {
                if wireguard_up; then
                    %s.sabanet "$@";
                elif same_global_subnet "%s"; then
                    %s.local "%@";
                else
                    %s.webmux "%@";
                fi;
            """%(name, name, s['global_ip'], name)

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
