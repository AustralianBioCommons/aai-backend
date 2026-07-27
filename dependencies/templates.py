from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

TEMPLATES = Jinja2Templates(
    env=Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(),
        undefined=StrictUndefined,
    ),
)


def get_templates():
    return TEMPLATES
