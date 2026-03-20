from django.db import models

def text_length(choices: type[models.TextChoices]) -> int:
    return max(map(len, choices.values))
