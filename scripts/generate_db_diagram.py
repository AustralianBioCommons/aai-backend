import sys

sys.path.append(".")
from sqlalchemy_data_model_visualizer import generate_data_model_diagram

from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    GroupMembershipHistory,
    PlatformMembership,
    PlatformMembershipHistory,
)

models = [
    BiocommonsUser,
    BiocommonsGroup,
    GroupMembership,
    GroupMembershipHistory,
    PlatformMembership,
    PlatformMembershipHistory,
    Auth0Role
]
generate_data_model_diagram(models, "db_diagram")
