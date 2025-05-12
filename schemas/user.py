from pydantic import BaseModel
from .tokens import AccessTokenPayload


class User(BaseModel):
    """
    Define our user model so we can implement any required
    permissions checks here, instead of doing individual
    checks in different places.
    """

    access_token: AccessTokenPayload

    def is_admin(self) -> bool:
        """
        Checks if the user has an admin role.
        """
        # TODO: Need to finalize exactly what roles make
        #   a user an admin
        for role in self.access_token.biocommons_roles:
            if "admin" in role.lower():
                return True
        return False
