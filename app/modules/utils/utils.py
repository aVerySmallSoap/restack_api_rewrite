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


def map_endpoints(endpoints: set) -> dict:
    """ Map's endpoints into a dictionary"""
    from urllib.parse import urlparse
    site_map: dict = {}
    for endpoint in endpoints:
        path = urlparse(endpoint).path
        segments = [segment for segment in path.split("/") if segment]

        current = site_map
        for segment in segments:
            current = current.setdefault(segment, {})
    return site_map