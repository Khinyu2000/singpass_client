class TokenRequestError(Exception):
    pass


class UnexpectedTokenError(Exception):
    pass


class BadSignatureError(Exception):
    pass


class InvalidClaimError(Exception):
    pass


class InfoRequestError(Exception):
    pass


class BadEncryptionError(Exception):
    pass


class BadCodeVerifierSizeError(Exception):
    pass


class InvalidKeyError(Exception):
    pass
