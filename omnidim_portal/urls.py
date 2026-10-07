from django.contrib import admin
from django.urls import path

from . import views

urlpatterns = [
    path("", views.index),
    path("login/", views.PortalLogin.as_view(), name="login"),
    path("admin/login/", views.PortalLogin.as_view()),
    path("admin/", admin.site.urls),
    path("health/live", views.live),
    path("health/ready", views.ready),
    path("api/<path:route>", views.api),
]
