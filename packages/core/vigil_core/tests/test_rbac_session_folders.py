"""Session FOLDERS are RBAC-mapped at the session tier.

Organising sessions into folders is the same kind of act as renaming or deleting a session, so the four
folder POST routes require exactly the permission ``/api/session/rename`` does (``run_engagement``,
operator+). A viewer or analyst cannot reorganise the console's sessions, and an unmapped neighbour path
stays DEFAULT-DENY (``None``), so the new entries widen nothing beyond their own four paths.
"""

from __future__ import annotations

import pytest

from vigil_core import rbac

FOLDER_POSTS = ("/api/folder/create", "/api/folder/rename", "/api/folder/delete", "/api/session/folder")


@pytest.mark.parametrize("path", FOLDER_POSTS)
def test_folder_routes_need_the_session_rename_permission(path):
    assert rbac.offense_perm_for(path) == rbac.offense_perm_for("/api/session/rename") == "run_engagement"


@pytest.mark.parametrize("path", FOLDER_POSTS)
@pytest.mark.parametrize("role,allowed", [("viewer", False), ("analyst", False),
                                          ("operator", True), ("owner", True)])
def test_folder_routes_by_role(path, role, allowed):
    assert rbac.role_can(role, rbac.offense_perm_for(path)) is allowed


@pytest.mark.parametrize("path", ["/api/folder/purge", "/api/folders/create", "/api/folder",
                                  "/api/session/folders", "/api/folder/create/x"])
def test_unmapped_neighbours_stay_default_deny(path):
    assert rbac.offense_perm_for(path) is None
