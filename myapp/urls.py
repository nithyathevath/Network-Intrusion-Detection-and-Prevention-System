from django.urls import path

from myapp import views

urlpatterns=[
    path('',views.home,name='home'),
    path('start_rds/', views.start_rds, name='start_rds'),
    path('stop_rds/', views.stop_rds, name='stop_rds'),
    path('download_security_report/', views.download_security_report, name='download_security_report'),
]
from django.conf import settings
from django.conf.urls.static import static

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)