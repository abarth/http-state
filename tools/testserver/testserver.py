#!/usr/bin/python2.4
# Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This is a simple HTTP server used for testing cookies.

It supports several test URLs, as specified by the handlers in TestPageHandler.
It defaults to living on localhost:8888.
To shut it down properly, visit localhost:8888/kill.
"""

import base64
import BaseHTTPServer
import cgi
import optparse
import os
import re
import shutil
import SocketServer
import sys
import time

SERVER_HTTP = 0

debug_output = sys.stderr
def debug(str):
  debug_output.write(str + "\n")
  debug_output.flush()

class StoppableHTTPServer(BaseHTTPServer.HTTPServer):
  """This is a specialization of of BaseHTTPServer to allow it
  to be exited cleanly (by setting its "stop" member to True)."""

  def serve_forever(self):
    self.stop = False
    self.nonce = None
    while not self.stop:
      self.handle_request()
    self.socket.close()

class TestPageHandler(BaseHTTPServer.BaseHTTPRequestHandler):

  def __init__(self, request, client_address, socket_server):
    self._connect_handlers = [
      self.DefaultConnectResponseHandler]
    self._get_handlers = [
      self.KillHandler,
      self.CookieParserHandler,
      self.CookieParserResultHandler,
      self.FileHandler,
      self.DefaultResponseHandler]
    self._post_handlers = [
      ] + self._get_handlers

    self._mime_types = {
      'gif': 'image/gif',
      'jpeg' : 'image/jpeg',
      'jpg' : 'image/jpeg'
    }
    self._default_mime_type = 'text/html'

    BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request,
                                                   client_address,
                                                   socket_server)

  def _ShouldHandleRequest(self, handler_name):
    """Determines if the path can be handled by the handler.

    We consider a handler valid if the path begins with the
    handler name. It can optionally be followed by "?*", "/*".
    """

    pattern = re.compile('%s($|\?|/).*' % handler_name)
    return pattern.match(self.path)

  def GetMIMETypeFromName(self, file_name):
    """Returns the mime type for the specified file_name. So far it only looks
    at the file extension."""

    (shortname, extension) = os.path.splitext(file_name)
    if len(extension) == 0:
      # no extension.
      return self._default_mime_type

    # extension starts with a dot, so we need to remove it
    return self._mime_types.get(extension[1:], self._default_mime_type)

  def KillHandler(self):
    """This request handler kills the server, for use when we're done"
    with the a particular test."""

    if (self.path.find("kill") < 0):
      return False

    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.send_header('Cache-Control', 'max-age=0')
    self.end_headers()
    self.wfile.write("Time to die")
    self.server.stop = True

    return True

  def CookieParserHandler(self):
    """The handler for cookie parser tests."""

    if not self._ShouldHandleRequest("/cookie-parser"):
      return False

    query_char = self.path.find('?')
    if query_char != -1:
      test = self.path[query_char+1:]

    path = self._parser_test_path(test)
    if not os.path.isfile(path):
      print "Test not found " + test + " full path:" + path
      self.send_error(404)
      return True

    self.send_response(302)

    have_sent_location = False
    f = open(path, "r")
    for line in f:
      # "name: value"
      name, value = re.findall('(\S+):\s*(.*)', line)[0]
      if name.lower() == "location":
        have_sent_location = True
      self.send_header(name, value)
    f.close()

    if not have_sent_location:
      self.send_header("Location", "/cookie-parser-result?" + test)
    self.end_headers()

    self.wfile.write("")

    return True

  def CookieParserResultHandler(self):
    """The handler that checks cookie parser test results."""

    if not self._ShouldHandleRequest("/cookie-parser-result"):
      return False

    query_char = self.path.find('?')
    if query_char != -1:
      test = self.path[query_char+1:]

    actual = self.headers.getheader('cookie')

    path = self._parser_expected_path(test)
    if not os.path.isfile(path):
      self.send_response(404)
      self.send_header("Content-Type", "text/plain")
      self.end_headers()
      self.wfile.write("Test not found " + test + " full path:" + path + "\n")
      if actual:
        self.wfile.write("Received Cookie: " + actual + "\n")
      return True

    f = open(path, "r")
    data = f.read()
    f.close()

    expected_headers = re.findall('Cookie:\s*(.*)', data)
    expected = expected_headers[0] if len(expected_headers) == 1 else None

    self.send_response(200)
    self.send_header("Content-Type", "text/plain")
    # Remove persistent test cookies.
    self.send_header("Set-Cookie", "foo=deleted; Expires=Fri, 07 Aug 2007 08:04:19 GMT")
    self.send_header("Set-Cookie", "foo2=deleted; Expires=Fri, 07 Aug 2007 08:04:19 GMT")
    self.send_header("Set-Cookie", "foo3=deleted; Expires=Fri, 07 Aug 2007 08:04:19 GMT")
    self.end_headers()
    
    if actual == expected:
      self.wfile.write("PASS\n")
    else:
      f = open(self._parser_test_path(test), "r")
      test_case = f.read()
      f.close()
      self.wfile.write("FAIL\nActual: %s\nExpected: %s\nTest Case:\n%s" % (actual, expected, test_case))

    return True

  def _parser_test_path(self, test):
    return os.path.join(self.server.data_dir, "parser", test + "-test")

  def _parser_expected_path(self, test):
    return os.path.join(self.server.data_dir, "parser", test + "-expected")

  def FileHandler(self):
    """This handler sends the contents of the requested file.  Wow, it's like
    a real webserver!"""

    prefix = self.server.file_root_url
    if not self.path.startswith(prefix):
      return False

    # Consume a request body if present.
    if self.command == 'POST':
      self.rfile.read(int(self.headers.getheader('content-length')))

    file = self.path[len(prefix):]
    entries = file.split('/');
    path = os.path.join(self.server.data_dir, *entries)
    if os.path.isdir(path):
      path = os.path.join(path, 'index.html')

    if not os.path.isfile(path):
      print "File not found " + file + " full path:" + path
      self.send_error(404)
      return True

    f = open(path, "rb")
    data = f.read()
    f.close()

    # If file.mock-http-headers exists, it contains the headers we
    # should send.  Read them in and parse them.
    headers_path = path + '.mock-http-headers'
    if os.path.isfile(headers_path):
      f = open(headers_path, "r")

      # "HTTP/1.1 200 OK"
      response = f.readline()
      status_code = re.findall('HTTP/\d+.\d+ (\d+)', response)[0]
      self.send_response(int(status_code))

      for line in f:
        # "name: value"
        name, value = re.findall('(\S+):\s*(.*)', line)[0]
        self.send_header(name, value)
      f.close()
    else:
      # Could be more generic once we support mime-type sniffing, but for
      # now we need to set it explicitly.
      self.send_response(200)
      self.send_header('Content-type', self.GetMIMETypeFromName(file))
      self.send_header('Content-Length', len(data))
    self.end_headers()

    self.wfile.write(data)

    return True

  def DefaultResponseHandler(self):
    """This is the catch-all response handler for requests that aren't handled
    by one of the special handlers above.
    Note that we specify the content-length as without it the https connection
    is not closed properly (and the browser keeps expecting data)."""

    contents = "Default response given for path: " + self.path
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.send_header("Content-Length", len(contents))
    self.end_headers()
    self.wfile.write(contents)
    return True

  def DefaultConnectResponseHandler(self):
    """This is the catch-all response handler for CONNECT requests that aren't
    handled by one of the special handlers above.  Real Web servers respond
    with 400 to CONNECT requests."""

    contents = "Your client has issued a malformed or illegal request."
    self.send_response(400)  # bad request
    self.send_header('Content-type', 'text/html')
    self.send_header("Content-Length", len(contents))
    self.end_headers()
    self.wfile.write(contents)
    return True

  def do_CONNECT(self):
    for handler in self._connect_handlers:
      if handler():
        return

  def do_GET(self):
    for handler in self._get_handlers:
      if handler():
        return

  def do_POST(self):
    for handler in self._post_handlers:
      if handler():
        return

  # called by the redirect handling function when there is no parameter
  def sendRedirectHelp(self, redirect_name):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write('<html><body><h1>Error: no redirect destination</h1>')
    self.wfile.write('Use <pre>%s?http://dest...</pre>' % redirect_name)
    self.wfile.write('</body></html>')

def MakeDataDir():
  if not options.data_dir:
    print 'please specify a data dir. exiting...'
    return None

  if not os.path.isdir(options.data_dir):
    print 'specified data dir not found: ' + options.data_dir + ' exiting...'
    return None

  return options.data_dir

def main(options, args):
  # redirect output to a log file so it doesn't spam the unit test output
  # Let's spam the console for now.
  # logfile = open('testserver.log', 'w')
  # sys.stderr = sys.stdout = logfile

  port = options.port

  server = StoppableHTTPServer(('127.0.0.1', port), TestPageHandler)
  print 'HTTP server started on port %d...' % port

  server.data_dir = MakeDataDir()
  server.file_root_url = options.file_root_url

  try:
    server.serve_forever()
  except KeyboardInterrupt:
    print 'shutting down server'
    server.stop = True

if __name__ == '__main__':
  option_parser = optparse.OptionParser()
  option_parser.add_option('', '--port', default='8888', type='int',
                           help='Port used by the server')
  option_parser.add_option('', '--data-dir', dest='data_dir',
                           help='Directory from which to read the files')
  option_parser.add_option('', '--file-root-url', default='/files/',
                           help='Specify a root URL for files served.')
  options, args = option_parser.parse_args()

  sys.exit(main(options, args))
