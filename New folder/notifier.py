"""
Compatibility shim.

Keep the public import name `notifier` stable while allowing the implementation
to live in `notifier111.py`.
"""

from notifier111 import *  # noqa: F403

