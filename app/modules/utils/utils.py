
def read_required_images() -> list[str]:
    collection: list[str] = []
    try:
        with open("./app/templates/docker/docker_images", "r") as f:
            for line in f.read().splitlines():
                collection.append(line)
    except FileNotFoundError as e:
        print(e) #log
        return []
    return collection

