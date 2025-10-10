from fastapi import APIRouter, Depends

from auth.user_permissions import user_is_biocommons_admin

router = APIRouter(prefix="/biocommons-admin", tags=["admin"],
                   dependencies=Depends(user_is_biocommons_admin))
