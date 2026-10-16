def first(items, **match):
    """First dict in ``items`` whose fields equal ``match``."""
    for it in items:
        if all(it.get(k) == v for k, v in match.items()):
            return it
    raise AssertionError(f"no item matching {match}")
