from pydantic import BaseModel


class Group(BaseModel):
    name: str
    id: str
