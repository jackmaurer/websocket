#!/usr/bin/env python

__version__ = "0.1"
__author__ = "Jack Maurer"

from distutils.core import setup

setup(name="websocket",
      version="0.1",
      author="Jack Maurer",
      author_email="jackmaurer@users.noreply.github.com",
      license="MIT License",
      description="Extensible WebSocket server and client",
      py_modules=["framing", "server", "client"])
