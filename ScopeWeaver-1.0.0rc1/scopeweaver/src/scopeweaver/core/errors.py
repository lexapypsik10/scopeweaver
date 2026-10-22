class ScopeWeaverError(Exception):
    """An expected assessment error suitable for a concise CLI message."""


class ScopeViolation(ScopeWeaverError):
    pass


class BudgetExceeded(ScopeWeaverError):
    pass


class NetworkError(ScopeWeaverError):
    pass


class StopRequested(ScopeWeaverError):
    pass
