"""Shared mailbox-provider exceptions.

Two very different failure classes must not be conflated:

* Fatal provider/config errors — bad API key, empty balance, out of stock,
  IP not allowed. These are raised as ``LitensiError`` / ``MailCxError``.
  Retrying the next account would fail identically, so the whole job aborts.

* Per-mailbox transient errors — a single mailbox never received the GitHub
  verification code within the timeout. This is raised as
  ``MailboxTimeoutError``. It must fail ONLY that account and let the batch
  continue; aborting a 50-account run because one mailbox timed out is wrong.
"""
from __future__ import annotations


class MailboxTimeoutError(RuntimeError):
    """No verification code arrived in time for a single mailbox.

    Deliberately NOT a subclass of ``LitensiError`` / ``MailCxError`` so the
    runner's fatal-provider-error handling does not catch it and abort the job.
    """


class MailboxCancelled(RuntimeError):
    """The wait for a verification code was cancelled (user pressed Stop).

    Also NOT a ``LitensiError`` / ``MailCxError`` so it is not reported as a
    provider failure. The runner converts it into a clean cancellation.
    """
