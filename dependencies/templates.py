from fastapi.templating import Jinja2Templates
from jinja2 import StrictUndefined

TEMPLATES = Jinja2Templates(
    directory="templates",
    autoescape=True,
    undefined=StrictUndefined,
)


def get_templates():
    return TEMPLATES
