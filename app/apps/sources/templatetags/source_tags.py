from django import template


register = template.Library()


@register.simple_tag
def source_sort_url(request, field):
    params = request.GET.copy()
    current_field = params.get("sort", "source")
    current_direction = params.get("direction", "asc")
    params["sort"] = field
    params["direction"] = "desc" if current_field == field and current_direction == "asc" else "asc"
    params.pop("page", None)
    return f"?{params.urlencode()}"


@register.simple_tag
def source_page_url(request, page):
    params = request.GET.copy()
    params["page"] = page
    return f"?{params.urlencode()}"


@register.simple_tag
def source_sort_indicator(request, field):
    if request.GET.get("sort", "source") != field:
        return "↕"
    return "↓" if request.GET.get("direction", "asc") == "desc" else "↑"
