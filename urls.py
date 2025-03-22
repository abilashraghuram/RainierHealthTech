from django.urls import path
from .views import de_identify_data

urlpatterns = [
    path('de-identify/', de_identify_data, name='de_identify_data'),
]