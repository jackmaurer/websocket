#!/usr/bin/env python3

__version__ = "0.1"
__author__ = "Jack Maurer"

from distutils.core import setup

setup(name="websocket",
      version="0.1",
      description="Extensible WebSocket server and client",
      author="Jack Maurer",
      py_modules=["framing", "server", "client"])
