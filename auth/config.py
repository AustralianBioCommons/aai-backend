from functools import lru_cache
from typing import Dict, List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    auth0_domain: str
    auth0_management_id: str
    auth0_management_secret: str
    auth0_audience: str
    jwt_secret_key: str
    auth0_algorithms: list[str] = ["RS256"]
    # Note we process this separately in app startup as it needs
    #   to be available before the app starts
    cors_allowed_origins: str
    organizations: List[Dict[str, str]] = [
        {"id": "bpa-bioinformatics-workshop", "name": "2024 Fungi Bioinformatics Workshop"},
        {"id": "cipps", "name": "ARC for Innovations in Peptide and Protein Science (CIPPS)"},
        {"id": "ausarg", "name": "Australian Amphibian and Reptile Genomics"},
        {"id": "aus-avian", "name": "Australian Avian Genomics"},
        {"id": "aus-fish", "name": "Australian Fish Genomics"},
        {"id": "grasslands", "name": "Australian Grasslands Initiative"},
        {"id": "fungi", "name": "Fungi Functional 'Omics"},
        {"id": "forest-resilience", "name": "Genomics for Forest Resilience"},
        {"id": "bpa-great-barrier-reef", "name": "Great Barrier Reef"},
        {"id": "bpa-ipm", "name": "Integrated Pest Management 'Omics"},
        {"id": "bpa-omg", "name": "Oz Mammals Genomics Initiative"},
        {"id": "plant-pathogen", "name": "Plant Pathogen 'Omics"},
        {"id": "ppa", "name": "Plant Protein Atlas"},
        {"id": "australian-microbiome", "name": "The Australian Microbiome Initiative"},
        {"id": "threatened-species", "name": "Threatened Species Initiative"},
        {"id": "bpa-wheat-cultivars", "name": "Wheat Cultivars"},
        {"id": "bpa-wheat-pathogens-genomes", "name": "Wheat Pathogens Genomes"},
        {"id": "bpa-wheat-pathogens-transcript", "name": "Wheat Pathogens Transcript"},
    ]

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache()
def get_settings():
    return Settings()
