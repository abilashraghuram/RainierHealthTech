from django.urls import path
from . import views

urlpatterns = [
    path('de-identify/', views.de_identify_data, name='de_identify_data'),
] 