import types

import bpa_register


class _Org:
    def __init__(self, name: str, title: str):
        self.name = name
        self.title = title


class _OKCkanClient:
    def get_autoregister_organizations(self):
        return [_Org(name="bpa", title="Bioplatforms Australia"),
                _Org(name="fungi", title="Fungi Functional 'Omics")]


class _FailingCkanClient:
    def get_autoregister_organizations(self):
        raise RuntimeError("ckan is down")


def test_get_bpa_autoregister_list_prefers_ckan():
    ckan = _OKCkanClient()
    settings = types.SimpleNamespace(
        # Would be ignored since CKAN succeeds:
        organizations={"legacy": "Legacy Title"}
    )
    mapping = bpa_register._get_bpa_autoregister_list(ckan, settings)
    assert mapping == {
        "bpa": "Bioplatforms Australia",
        "fungi": "Fungi Functional 'Omics",
    }


def test_get_bpa_autoregister_list_fallback_on_error():
    ckan = _FailingCkanClient()
    settings = types.SimpleNamespace(
        organizations={"legacy": "Legacy Title", "bpa": "Bioplatforms Australia"}
    )
    mapping = bpa_register._get_bpa_autoregister_list(ckan, settings)
    # Falls back entirely to the static settings
    assert mapping == settings.organizations
