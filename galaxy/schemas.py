from typing import Optional

from pydantic import BaseModel, NaiveDatetime


class GalaxyUserModel(BaseModel):
    """
    User data returned by Galaxy's users API
    """
    model_class: str
    id: str
    username: str
    email: str
    deleted: bool
    active: bool
    last_password_change: Optional[NaiveDatetime]
