class WrongCredentialsException(Exception):
    """Exception thrown when wrong credentials are given"""

class BadLoginException(Exception):
    """Exception thrown when wrong user/pass are given"""

class ScanNotFoundException(Exception):
    """Exception that raises when there are given an UUID who doesnt exists"""

class WrongParametersException(Exception):
    """Exception that raises when there are inserted wrong parameters in the api"""