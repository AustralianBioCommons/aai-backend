import sys

sys.path.append(".")
from sqlalchemy_data_model_visualizer import generate_data_model_diagram

from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    BiocommonsUserHistory,
    EmailChangeOtp,
    EmailNotification,
    GroupMembership,
    GroupMembershipHistory,
    Platform,
    PlatformMembership,
    PlatformMembershipHistory,
)

models = [
    BiocommonsUser,
    BiocommonsUserHistory,
    BiocommonsGroup,
    GroupMembership,
    GroupMembershipHistory,
    Platform,
    PlatformMembership,
    PlatformMembershipHistory,
    Auth0Role,
    EmailNotification,
    EmailChangeOtp,
]
generate_data_model_diagram(models, "db_diagram")
