#!/usr/bin/env python
# -*- coding: utf-8
# pylint: disable=W0212
"""
Purpose: Implement daemon process class
Created: 21.11.2012
Author: yac
"""

import os
import sys
import time
import errno
from signal import SIGTERM, SIGKILL


class Daemon():
    """Implement daemon process class."""

    def __init__(self, pid_file='', std_in='/dev/null', std_out='/dev/null', std_err='/dev/null'):
        self.pid_file = pid_file
        self.std_in = std_in
        self.std_out = std_out
        self.str_err = std_err

    def __daemonize(self):
        """Fork Unix process"""
        try:
            # Store the Fork PID
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, error:
            sys.stderr.write('Unable to fork. Error: %d (%s)' % (error.errno, error.strerror))
            sys.exit(1)

        pid = str(os.getpid())
        file(self.pid_file, 'w+').write("%s\n" % pid)

    def __descriptors(self):
        """redirect standard file descriptors"""
        sys.stdout.flush()
        sys.stderr.flush()
        std_in = file(self.std_in, 'r')
        std_out = open(self.str_err, 'a+')
        std_err = open(self.str_err, 'a+', 0)
        os.dup2(std_in.fileno(), sys.stdin.fileno())
        os.dup2(std_out.fileno(), sys.stdout.fileno())
        os.dup2(std_err.fileno(), sys.stderr.fileno())

    def pid_exists(self, pid):
        """Check whether pid exists in the current process table."""
        if pid < 0:
            return False
        try:
            os.kill(pid, 0)
        except OSError, e:
            return e.errno == errno.EPERM
        else:
            return True

    def start(self):
        """Start the daemon"""
        try:
            with open(self.pid_file) as pid_file:
                pid = int(pid_file.read().strip())
        except IOError:
            pid = None

        if pid:
            if self.pid_exists(pid):
                sys.stderr.write('Daemon already running. (pid=%s)\n' % pid)
                sys.exit(1)
            else:
                try:    
                    os.remove(self.pid_file)
                except OSError, err:
                    sys.stderr.write(str(err))
                    sys.exit(1)

        self.__daemonize()
#        self.__descriptors()
        self.run()

    def stop(self):
        """ Stop the daemon """
        try:
            with open(self.pid_file) as pid_file:
                pid = int(pid_file.read().strip())

        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. Daemon not running?\n"
            sys.stderr.write(message % self.pid_file)
            return  # not an error in a restart
        elif str(pid) == str(os.getpid()):
            return

        # Try killing the daemon process
        try:
            i = 0
            while i < 5:
                i += 1
                os.kill(pid, SIGTERM)
                time.sleep(0.5)
            os.kill(pid, SIGKILL)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pid_file):
                        os.remove(self.pid_file)
            else:
                sys.stderr.write(str(err))
                sys.exit(1)

    def restart(self):
        """Restart the daemon"""
        self.stop()
        self.start()

    @classmethod
    def run(cls):
        """Run daemon process"""
        sys.stderr.write("ERROR: Daemon not started\nYou need to override run() method in your subclass!\n")
        sys.exit(1)