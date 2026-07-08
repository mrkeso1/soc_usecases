from django import template

from apps.usecases.text_utils import split_multi_value

register = template.Library()


@register.filter
def split_multi(value):
    return split_multi_value(value)
