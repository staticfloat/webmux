#!/usr/bin/env python
from __future__ import print_function, absolute_import
import logging
import os, os.path
import sys, subprocess

import tornado.web
from tornado.netutil import bind_unix_socket
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.log import enable_pretty_logging
import tornado.options
# This demo requires tornado_xstatic and XStatic-term.js
import tornado_xstatic
import terminado

STATIC_DIR = os.path.join(os.path.dirname(terminado.__file__), "_static")
TEMPLATE_DIR = os.path.dirname(__file__)

# TODO: Read some kind of database to auto-populate server_list and port_list
port_base = 2222
server_list = {}

def kill_all_tunnels():
    lsof_cmd = "sudo lsof -i:%d-%d -P -n"%(port_base, port_base+50)
    lsof_output = subprocess.check_output(lsof_cmd.split())
    ssh_procs = list(set([l.split()[1] for l in lsof_output.split('\n')[1:] if l]))
    for p in ssh_procs:
        subprocess.call(["sudo", "kill", p])
    return ssh_procs

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

        # Create new terminal
        logging.info("Attempting to connect to port: %s", port_number)
        self.shell_command = ["ssh", "-p", port_number, "localhost"]
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
    def get(self, hostname):
        if not hostname in server_list:
            if len(server_list) == 0:
                port_number = port_base
            else:
                port_number = max([int(server_list[k]) for k in server_list]) + 1

            logging.info("Mapping %s to port %d"%(hostname, port_number))
            server_list[hostname] = str(port_number)
        self.write(server_list[hostname])

class ResetPageHandler(tornado.web.RequestHandler):
    """Reset all SSH connections forwarding ports"""
    def get(self, hostname):
        ssh_procs = kill_all_tunnels()
        logging.info("Killed %d SSH tunnels"%(len(ssh_procs)))
        self.write("Killed %d SSH tunnels"%(len(ssh_procs)))

class TerminalPageHandler(tornado.web.RequestHandler):
    def get_host(self, port_number):
        for hostname in server_list:
            if server_list[hostname] == port_number:
                return hostname
        return "host on port " + port_number

    """Render the /shell/[\d]+ pages"""
    def get(self, port_number):
        return self.render("term.html", static=self.static_url,
                           xstatic=self.application.settings['xstatic_url'],
                           ws_url_path="/_websocket/"+port_number,
                           hostname=self.get_host(port_number))


if __name__ == "__main__":
    # Parse things like --loglevel
    tornado.options.parse_command_line()

    term_manager = WebmuxTermManager(shell_command=["echo"], max_terminals=100)

    handlers = [
        (r"/", IndexPageHandler),
        (r"/reset", ResetPageHandler),
        (r"/register/(.*)", RegistrationPageHandler),
        (r"/_websocket/(\w+)", terminado.TermSocket, {'term_manager': term_manager}),
        (r"/shell/([\d]+)/?", TerminalPageHandler),
        (r"/xstatic/(.*)", tornado_xstatic.XStaticFileHandler),
    ]
    application = tornado.web.Application(handlers, static_path=STATIC_DIR,
                              template_path=TEMPLATE_DIR,
                              xstatic_url=tornado_xstatic.url_maker('/xstatic/'),
                              term_manager=term_manager)

    SOCKET_PATH = "/tmp/webmux.socket"
    socket = bind_unix_socket(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0777)
    server = HTTPServer(application)
    server.add_socket(socket)
    enable_pretty_logging()

    try:
        # If we restarted or something, then be sure to cause all tunnels to reconnect
        logging.info("Killed %d SSH tunnels"%(len(kill_all_tunnels())))
        logging.info("All systems operational, commander")
        IOLoop.current().start()
    except KeyboardInterrupt:
        logging.info("\nShutting down due to SIGINT")
    finally:
        term_manager.shutdown()
        IOLoop.current().close()
