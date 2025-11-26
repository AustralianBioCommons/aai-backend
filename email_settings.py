"""
Shared email configuration defaults.
"""

import os


DEFAULT_EMAIL_SENDER = os.environ.get("DEFAULT_EMAIL_SENDER", "amanda@biocommons.org.au")
