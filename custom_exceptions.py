class InvalidFlagError(Exception):
    def __init__(self, message):
        super().__init__(message)


class InvalidIPError(Exception):
    def __init__(self, message="Address is invalid IP format"):
        super().__init__(message)


class InvalidPortError(Exception):
    def __init__(self, message="Port is not valid port"):
        super().__init__(message)


class InvalidProtocolError(Exception):
    def __init__(self, message="Protocol must be TCP or UDP"):
        super().__init__(message)