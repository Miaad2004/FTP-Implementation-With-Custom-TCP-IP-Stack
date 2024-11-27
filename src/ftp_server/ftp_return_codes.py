
class FTPReturnCodes:
    """
    Contains FTP return codes and their corresponding messages.
    """

    codes = {
        200: "Command okay.",
        500: "Syntax error, command unrecognized.",
        501: "Syntax error in parameters or arguments.",
        202: "Command not implemented, superfluous at this site.",
        502: "Command not implemented.",
        503: "Bad sequence of commands.",
        504: "Command not implemented for that parameter.",
        110: "Restart marker reply.",
        211: "System status, or system help reply.",
        212: "Directory status.",
        213: "File status.",
        214: "Help message.",
        215: "NAME system type.",
        120: "Service ready in nnn minutes.",
        220: "Service ready for new user.",
        221: "Service closing control connection.",
        421: "Service not available, closing control connection.",
        125: "Data connection already open; transfer starting.",
        225: "Data connection open; no transfer in progress.",
        425: "Can't open data connection.",
        226: "Closing data connection.",
        426: "Connection closed; transfer aborted.",
        227: "Entering Passive Mode.",
        230: "User logged in, proceed.",
        530: "Not logged in.",
        331: "User name okay, need password.",
        332: "Need account for login.",
        532: "Need account for storing files.",
        150: "File status okay; about to open data connection.",
        250: "Requested file action okay, completed.",
        257: "PATHNAME created.",
        350: "Requested file action pending further information.",
        450: "Requested file action not taken.",
        550: "Requested action not taken.",
        451: "Requested action aborted: local error in processing.",
        551: "Requested action aborted: page type unknown.",
        452: "Requested action not taken. Insufficient storage\
            space in system.",
        552: "Requested file action aborted. Exceeded storage allocation.",
        553: "Requested action not taken. File name not allowed."
    }

    @classmethod
    def get_message(cls, code: int) -> str:
        """
        Get the message corresponding to the FTP return code.

        :param code: The FTP return code.
        :return: The corresponding message.
        """
        return cls.codes.get(code, "Unknown return code.")