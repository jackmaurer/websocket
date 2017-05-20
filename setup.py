#!/usr/bin/env python

__version__ = "1.0"
__author__ = "Jack Maurer"

from distutils.core import setup

setup(name="websocket",
      version="1.0",
      author="Jack Maurer",
      author_email="jackmaurer@users.noreply.github.com",
      license="MIT License",
      description="Extensible WebSocket server",
      py_modules=["framing", "server"])
