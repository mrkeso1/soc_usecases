from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    display_name = models.CharField(max_length=255, blank=True)
    ldap_dn = models.CharField(max_length=512, blank=True)
    area = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.display_name or self.username