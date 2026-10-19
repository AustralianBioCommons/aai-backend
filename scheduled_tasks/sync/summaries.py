from __future__ import annotations

from typing import Self

from pydantic import BaseModel


class SyncSummary(BaseModel):
    """Base class for sync summaries whose fields are all integer counters."""

    def merge(self, other: Self) -> None:
        if type(other) is not type(self):
            raise TypeError(
                f"Cannot merge {type(other).__name__} into {type(self).__name__}"
            )

        for field_name in type(self).model_fields:
            setattr(self, field_name, getattr(self, field_name) + getattr(other, field_name))
