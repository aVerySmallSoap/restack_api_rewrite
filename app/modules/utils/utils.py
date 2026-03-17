
def read_required_images() -> list[str]:
    collection: list[str] = []
    with open("./app/utils/templates/docker_images", "r") as f:
        for line in f.read().splitlines():
            collection.append(line)
    return collection

