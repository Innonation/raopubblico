# -*- coding: utf-8 -*-

# Core Django imports
from django.conf.urls import url, include

# Imports from your apps
from django.urls import path

from agency import views
from agency.views import handler404

urlpatterns = [
    url('agency/', include('agency.urls')),
    path('agency/api/', include('agency.api.urls_api')),
    url(r'^$', views.login, name='login'),

]
