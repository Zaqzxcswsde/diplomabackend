# all of the possible error codes that the serializers can return


class ErrorCodes:
    # TICKET
    DATA_SHOULD_BE_DICT = "DATA_SHOULD_BE_DICT"
    INCORRECT_DICT_KEYS_TICKET = "INCORRECT_DICT_KEYS_TICKET"
    MALFORMED_JWT_SIGNATURE = "MALFORMED_JWT_SIGNATURE"
    INCORR_JWT_TICKET = "INCORR_JWT_TICKET"
    COULDNT_DECRYPT = "COULDNT_DECRYPT"
    ERR_IN_SIG_OR_DEC = "ERR_IN_SIG_OR_DEC"
    DEC_NOT_DICT = "DEC_NOT_DICT"
    UNSUP_VER_TICKET = "UNSUP_VER_TICKET"
    FLOW_CONTROL_ERROR = "FLOW_CONTROL_ERROR"
    REQ_TIME_FUTURE = "REQ_TIME_FUTURE"
    TICKET_EXPIRED = "TICKET_EXPIRED"
    PUBKEYS_MISMATCH = "PUBKEYS_MISMATCH"
    UNREGISTERED_TICKET = "UNREGISTERED_TICKET"
    INACTIVE_TICKET = "INACTIVE_TICKET"
    # TOKEN
    NEW_TKN_NOT_ALLOWED = "NEW_TKN_NOT_ALLOWED"
    CANNOT_CREATE_TICKET_UNREGISTERED = "CANNOT_CREATE_TICKET_UNREGISTERED"
    TKN_DATA_NOT_DICT = "TKN_DATA_NOT_DICT"
    INCORRECT_DICT_KEYS_TOKEN = "INCORRECT_DICT_KEYS_TOKEN"
    INCORR_JWT_TOKEN = "INCORR_JWT_TOKEN"
    INCORR_TOKEN_KEYS = "INCORR_TOKEN_KEYS"
    UNSUP_APP_VERSION = "UNSUP_APP_VERSION"
    PUBKEY_INCORR_FMT = "PUBKEY_INCORR_FMT"
    MALFORMED_JWT_SIGNATURE_TOKEN = "MALFORMED_JWT_SIGNATURE_TOKEN"
    TICKET_IS_REQUIRED = "TICKET_IS_REQUIRED"
    NEW_TKN_SHOULDNT_TICKETS = "NEW_TKN_SHOULDNT_TICKETS"
    NOT_A_VALID_IP = "NOT_A_VALID_IP"
    PIN_IS_INVALID = "PIN_IS_INVALID"
    REQ_TIME_TOKEN_FUTURE = "REQ_TIME_TOKEN_FUTURE"
    REQ_TOO_OLD = "REQ_TOO_OLD"
    TOKEN_IS_UNREGISTERED = "TOKEN_IS_UNREGISTERED"
    INACTIVE_TOKEN = "INACTIVE_TOKEN"


SEARCHABLE_ERROR_CODES = [
    ErrorCodes.PIN_IS_INVALID,
    ErrorCodes.INACTIVE_TOKEN,
    ErrorCodes.NOT_A_VALID_IP,
    ErrorCodes.TOKEN_IS_UNREGISTERED,
    ErrorCodes.UNSUP_APP_VERSION,
    ErrorCodes.TICKET_EXPIRED,
    ErrorCodes.UNSUP_VER_TICKET,
    ErrorCodes.FLOW_CONTROL_ERROR,
]


ERRORS = {
    # TICKET
    ErrorCodes.DATA_SHOULD_BE_DICT: "ticket data should be dict",
    ErrorCodes.INCORRECT_DICT_KEYS_TICKET: "incorrect dictionary passed, keys() should be == ['ticket']",
    ErrorCodes.MALFORMED_JWT_SIGNATURE: "malformed JWT signature, ticket",
    ErrorCodes.INCORR_JWT_TICKET: "incorrect JWT token passed, ticket",
    ErrorCodes.COULDNT_DECRYPT: "couldn't decrypt payload",
    ErrorCodes.ERR_IN_SIG_OR_DEC: "error in signature verification or in decryption",
    ErrorCodes.DEC_NOT_DICT: "decrypted data is not dict",
    ErrorCodes.UNSUP_VER_TICKET: "unsupported ticket version",
    ErrorCodes.FLOW_CONTROL_ERROR: "flow control error, token has been deactivated for security reasons, the incident has been logged",
    ErrorCodes.REQ_TIME_FUTURE: "ticket request time is in the future somehow",
    ErrorCodes.TICKET_EXPIRED: "ticket has expired",
    ErrorCodes.PUBKEYS_MISMATCH: "public_keys mismatch. Is that an old token?",
    ErrorCodes.UNREGISTERED_TICKET: "that token is not registered in the database, ticket",
    ErrorCodes.INACTIVE_TICKET: "that token is not active, ticket",
    # TOKEN
    ErrorCodes.NEW_TKN_NOT_ALLOWED: "coulnt create token: new tokens are not allowed",
    ErrorCodes.CANNOT_CREATE_TICKET_UNREGISTERED: "coulnt create ticket: that token is not registered in the database",
    ErrorCodes.TKN_DATA_NOT_DICT: "token data should be dict",
    ErrorCodes.INCORRECT_DICT_KEYS_TOKEN: "incorrect dictionary passed, keys() should be == ['token']",
    ErrorCodes.INCORR_JWT_TOKEN: "incorrect JWT token passed, token",
    ErrorCodes.INCORR_TOKEN_KEYS: "incorrect token keys. ",
    ErrorCodes.UNSUP_APP_VERSION: "unsupported app version",
    ErrorCodes.PUBKEY_INCORR_FMT: "public_key is not in correct format: ",
    ErrorCodes.MALFORMED_JWT_SIGNATURE_TOKEN: "malformed JWT signature, token",
    ErrorCodes.TICKET_IS_REQUIRED: "ticket is required for existing tokens",
    ErrorCodes.NEW_TKN_SHOULDNT_TICKETS: "new tokens shouldn't have tickets",
    ErrorCodes.NOT_A_VALID_IP: "not a valid IP",
    ErrorCodes.PIN_IS_INVALID: "pin is invalid",
    ErrorCodes.REQ_TIME_TOKEN_FUTURE: "request_time is in the future, check time zones",
    ErrorCodes.REQ_TOO_OLD: "request_time is too old, send new request",
    ErrorCodes.TOKEN_IS_UNREGISTERED: "that token is not registered in the database, token",
    ErrorCodes.INACTIVE_TOKEN: "that token is not active, token",
}