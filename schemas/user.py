from pydantic import BaseModel

from auth.config import Settings

from .tokens import AccessTokenPayload


class SessionUser(BaseModel):
    """
    Represents the current user of the AAI Portal, and their session data (e.g. access token).

    NOTE: doesn't represent a user in the Auth0 database - see the schemas
    in schemas.biocommons for that
    """

    access_token: AccessTokenPayload

    def is_admin(self, settings: Settings) -> bool:
        """
        Checks if the user has an admin role.
        """
        # TODO: Need to finalize exactly what roles make
        #   a user an admin
        for role in self.access_token.biocommons_roles:
            if role in settings.admin_roles:
                return True
        return False
