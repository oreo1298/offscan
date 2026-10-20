"""Privileged helper: device discovery, unlocking, read-only mounting, file access.

Runs as root, started on demand by the client (pkexec, or directly when the
client is already root).  It speaks the JSON-lines protocol on stdin/stdout,
lives in an empty network namespace, and exits when stdin closes.
"""
