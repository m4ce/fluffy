class NotImplemented(Exception):
    pass

# Services


class ServiceError(Exception):
    pass


class ServiceExists(ServiceError):
    pass


class ServiceNotFound(ServiceError):
    pass


class ServiceNotValid(ServiceError):
    pass


class ServiceInUse(ServiceError):
    def __init__(self, message, deps):
        super(ServiceInUse, self).__init__(message)
        self.deps = deps


class ServiceNotUpdated(ServiceError):
    pass

# Sessions


class SessionError(Exception):
    pass


class SessionNotFound(SessionError):
    pass


class SessionExists(SessionError):
    pass


class SessionCommitError(SessionError):
    pass

# Rules


class RuleError(Exception):
    pass


class RuleExists(RuleError):
    pass


class RuleNotFound(RuleError):
    pass


class RuleNotValid(RuleError):
    pass


class RuleNotUpdated(RuleError):
    pass

# Chains


class ChainError(Exception):
    pass


class ChainExists(ChainError):
    pass


class ChainNotFound(ChainError):
    pass


class ChainNotValid(ChainError):
    pass


class ChainInUse(ChainError):
    def __init__(self, message, deps):
        super(ChainInUse, self).__init__(message)
        self.deps = deps


class ChainNotUpdated(ChainError):
    pass

# Interfaces


class InterfaceError(Exception):
    pass


class InterfaceExists(InterfaceError):
    pass


class InterfaceNotFound(InterfaceError):
    pass


class InterfaceNotValid(InterfaceError):
    pass


class InterfaceInUse(InterfaceError):
    def __init__(self, message, deps):
        super(InterfaceInUse, self).__init__(message)
        self.deps = deps


class InterfaceNotUpdated(InterfaceError):
    pass

# AddressBook


class AddressError(Exception):
    pass


class AddressExists(AddressError):
    pass


class AddressNotFound(AddressError):
    pass


class AddressNotValid(AddressError):
    pass


class AddressInUse(AddressError):
    def __init__(self, message, deps):
        super(AddressInUse, self).__init__(message)
        self.deps = deps


class AddressNotUpdated(AddressError):
    pass

# Rollback checks


class CheckError(Exception):
    pass


class CheckExists(CheckError):
    pass


class CheckNotFound(CheckError):
    pass


class CheckNotValid(CheckError):
    pass


class CheckNotUpdated(CheckError):
    pass
