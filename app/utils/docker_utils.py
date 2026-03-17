from app.utils.utils import read_required_images

def check_and_update_images():
    # Measure the performance of this function
    import docker
    print("Checking images are up-to-date")
    client = docker.from_env()
    requirements: list[str] = read_required_images()
    images = client.images.list()
    # blocking btw
    if not images:
        print("No images found\n Filling with requirements")
        for req in requirements:
            client.images.pull(req)
    else:
        for req in requirements:
            if req not in images:
                print("Requesting image: {}".format(req))
                client.images.pull(req)
    print("Images updated")