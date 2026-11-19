import hashlib
import secrets
from typing import Self

from pydantic import BaseModel

OTP_EXPIRATION_MINUTES = 10
MAX_TOTAL_ATTEMPTS = 10
OTP_LENGTH = 6


class OneTimePassword(BaseModel):
    """
    One time password used to verify email addresses.

    OTPs are random digits of length OTP_LENGTH.
    """
    code: str
    hash: str

    @staticmethod
    def _generate_code():
        return "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))

    @staticmethod
    def _get_hash_string(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @classmethod
    def generate(cls) -> Self:
        code = cls._generate_code()
        hash = cls._get_hash_string(code)
        return OneTimePassword(code=code, hash=hash)

    @classmethod
    def check_code(cls, code: str, hash: str) -> bool:
        """
        Check if given code matches the hash
        """
        hashed = cls._get_hash_string(code)
        return secrets.compare_digest(hashed, hash)
