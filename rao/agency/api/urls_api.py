# -*- coding: utf-8 -*-

# Core Django imports
from django.urls import path

# Imports from your apps
from agency.api.api import AuthViewSet, TokenViewSet, LOGViewSet

urlpatterns = [
    path('auth', AuthViewSet.as_view({'post': 'post'})),
    path('token', TokenViewSet.as_view()),
    path('log/<str:date>', LOGViewSet.as_view()),
]
