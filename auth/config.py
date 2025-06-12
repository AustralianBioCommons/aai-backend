from functools import lru_cache
from typing import Dict

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    auth0_domain: str
    auth0_management_id: str
    auth0_management_secret: str
    auth0_audience: str
    jwt_secret_key: str
    auth0_algorithms: list[str] = ["RS256"]
    admin_roles: list[str] = []
    # Note we process this separately in app startup as it needs
    #   to be available before the app starts
    cors_allowed_origins: str
    organizations: Dict[str, str] = {
        "bpa-bioinformatics-workshop": "2024 Fungi Bioinformatics Workshop",
        "cipps": "ARC for Innovations in Peptide and Protein Science (CIPPS)",
        "ausarg": "Australian Amphibian and Reptile Genomics",
        "aus-avian": "Australian Avian Genomics",
        "aus-fish": "Australian Fish Genomics",
        "grasslands": "Australian Grasslands Initiative",
        "fungi": "Fungi Functional 'Omics",
        "forest-resilience": "Genomics for Forest Resilience",
        "bpa-great-barrier-reef": "Great Barrier Reef",
        "bpa-ipm": "Integrated Pest Management 'Omics",
        "bpa-omg": "Oz Mammals Genomics Initiative",
        "plant-pathogen": "Plant Pathogen 'Omics",
        "ppa": "Plant Protein Atlas",
        "australian-microbiome": "The Australian Microbiome Initiative",
        "threatened-species": "Threatened Species Initiative",
        "bpa-wheat-cultivars": "Wheat Cultivars",
        "bpa-wheat-pathogens-genomes": "Wheat Pathogens Genomes",
        "bpa-wheat-pathogens-transcript": "Wheat Pathogens Transcript",
    }

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache()
def get_settings():
    return Settings()
