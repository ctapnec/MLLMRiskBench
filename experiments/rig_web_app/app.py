"""Composed socket-free rig web application."""

from __future__ import annotations

from .builder_capture import BuilderCaptureMixin
from .builder_models import BuilderModelsMixin
from .builder_page import BuilderPageMixin
from .builder_validation import BuilderValidationMixin
from .dashboard import DashboardMixin
from .lifecycle import LifecycleMixin
from .pages import PagesMixin
from .settings import SettingsMixin
from .workspace_pages import WorkspacePagesMixin


class RigWebApp(
    WorkspacePagesMixin,
    LifecycleMixin,
    DashboardMixin,
    BuilderModelsMixin,
    BuilderCaptureMixin,
    BuilderValidationMixin,
    BuilderPageMixin,
    SettingsMixin,
    PagesMixin,
):
    """Socket-free request core; the HTTP layer only delegates here."""
