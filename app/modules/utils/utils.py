def read_required_images() -> list[str]:
    from loguru import logger
    collection: list[str] = []
    try:
        with open("./app/templates/docker/docker_images", "r") as f:
            for line in f.read().splitlines():
                collection.append(line)
    except FileNotFoundError:
        logger.exception("docker_images file not found!")
        return []
    return collection

# Discovery utils

def map_endpoints(endpoints: set) -> dict:
    """ Map's endpoints into a dictionary"""
    from urllib.parse import urlparse
    site_map: dict = {}

    for endpoint in endpoints:
        path = urlparse(endpoint).path
        has_trailing = path.endswith("/") and path != "/"
        segments = [segment for segment in path.split("/") if segment]
        current = site_map.setdefault("/", {})

        for segment in segments:
            current = current.setdefault(segment, {})
        if has_trailing:
            current["/"] = {}
    return site_map

def is_same_host(host: str, endpoint: str) -> bool:
    """ Checks if the given endpoint matches the given host. The host is assumed to be already in a parsed state i.e, urlparse(host).netloc"""
    from urllib.parse import urlparse
    return host == urlparse(endpoint).netloc