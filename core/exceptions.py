"""Shared exceptions for the educational cryptocurrency project."""


class InvalidChainError(Exception):
    """Raised when the supplied Chain does not pass Chain.validate()."""


class InvalidBlockError(Exception):
    """Raised when a candidate block fails structural validation against its
    predecessor: a non-integer or non-contiguous index, a block hash that does
    not match its own contents, or a broken previous-hash link.

    The per-block counterpart to ``InvalidChainError``; raised by the ledger
    when validating a detached candidate block against a supplied prior state
    (see ``core.ledger``).
    """


class InvalidTransactionError(Exception):
    """Raised when a transaction record is malformed or invalid."""


class InvalidSignatureError(Exception):
    """Raised when a well-formed transaction has an invalid signature."""


class InsufficientFundsError(Exception):
    """Raised when a transfer would make a balance negative."""


class InvalidNonceError(Exception):
    """Raised when a transaction nonce is structurally valid but violates the
    account's expected-nonce continuity rule.

    Enforced by the ledger during deterministic replay (see ``core.ledger``).
    Structural/format problems in a serialized record belong to
    ``InvalidTransactionError``.
    """


class WrongChainError(Exception):
    """Raised when a transaction's ``chain_id`` does not match the chain being
    processed.

    Enforced by the ledger during deterministic replay, which binds every
    replay to one configured chain id (see ``core.ledger``).
    """
