"""Shared exceptions for the educational cryptocurrency project."""


class InvalidChainError(Exception):
    """Raised when the supplied Chain does not pass Chain.validate()."""


class InvalidTransactionError(Exception):
    """Raised when a transaction record is malformed or invalid."""


class InvalidSignatureError(Exception):
    """Raised when a well-formed transaction has an invalid signature."""


class InsufficientFundsError(Exception):
    """Raised when a transfer would make a balance negative."""
