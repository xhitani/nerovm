"""
Compatibility shim.

Keep the public import name `dashboard` stable while allowing the implementation
to live in `dashboard111.py`.
"""

from dashboard111 import *  # noqa: F403

