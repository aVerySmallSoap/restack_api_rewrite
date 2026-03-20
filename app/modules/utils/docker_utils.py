from app.modules.utils.utils import read_required_images

async def check_and_update_images():
    # Measure the performance of this function
    import docker
    from loguru import logger
    logger.info("Checking if images are up-to-date")
    client = docker.from_env()
    requirements: list[str] = read_required_images()
    images = []
    for image in client.images.list():
        if len(image.tags) != 0:
            images.append(image.tags[0])
    # blocking btw
    if not images:
        logger.warning("No images found. Checking image requirements")
        for req in requirements:
            client.images.pull(req)
        logger.success("Images pulled and updated")
        return
    else:
        for req in requirements:
            if req not in images:
                logger.warning(f"Image {req} not found")
                logger.warning(f"Requesting image: {req}")
                client.images.pull(req)