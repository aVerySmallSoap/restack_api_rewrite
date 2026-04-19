from pathlib import Path

from app.modules.utils.utils import read_required_images

def ensure_podman_docker_presence():
    """
    This function should try and check if podman/docker is present on the host.
    The function itself should stop the application from running if podman/docker API is not responding.
    """
    from docker import from_env as docker_from_env, errors as docker_errors
    from loguru import logger
    try:
        client = docker_from_env()
        if not client.api.api_version:
            raise docker_errors.DockerException("No API version found!")
        # Podman/Docker should be present and the usual checks should be good to go
        ensure_named_volumes()
        check_images()
        check_nuclei_templates()
        start_zap_service()
        wait_for_zap_or_crash()
    except docker_errors.APIError as e:
        logger.error("Podman/Docker API is not responding! Shutting down server...")
        raise Exception(e)
    except docker_errors.DockerException as e:
        logger.error(f"Something unexpected happened to the container API!\n {e}")
        logger.error("Shutting down server...")
        raise Exception("Something unexpected happened!")

def ensure_named_volumes():
    """This function should create named volumes for container specific storages"""
    from docker import from_env as docker_from_env, errors as docker_errors
    from loguru import logger
    logger.info("Check if named volumes are present on host")
    try:
        client = docker_from_env()
        volumes: list[str] = [volume.name for volume in client.volumes.list()]
        if "zap_volume" not in volumes:
            client.volumes.create("zap_volume")
    except docker_errors.APIError:
        raise docker_errors.APIError
    except docker_errors.DockerException as e:
        raise docker_errors.DockerException(e)

def check_images():
    from docker import errors as docker_errors, from_env as docker_from_env
    from loguru import logger
    logger.info("Checking if all required images are present")
    requirements: list[str] | None = read_required_images()
    try:
        client = docker_from_env()
        images = [entry.tags[0] for entry in client.images.list()] if len(client.images.list()) != 0 else None
        if not requirements:
            return None
        if not images:
            raise docker_errors.DockerException("No images found!")
        for req in requirements:
            if req not in images:
                logger.warning(f"Image {req} not found")
                logger.warning(f"Requesting image: {req}")
                client.images.pull(req)
        logger.info("Required images are present")
    except docker_errors.APIError:
        raise docker_errors.APIError
    except docker_errors.DockerException as e:
        raise docker_errors.DockerException(e)

def check_nuclei_templates():
    from docker import from_env as docker_from_env, errors as docker_errors
    from loguru import logger
    logger.info("Updating nuclei templates")
    client = docker_from_env()
    try:
        client.containers.run(
            image="projectdiscovery/nuclei",
            name="nuclei_template_updater",
            command=[
                "-ut"
            ],
            volumes={
                f"{Path.cwd()}/app/templates/nuclei/": {
                    "bind": "/root/nuclei-templates",
                    "mode": "rw",
                }
            },
            auto_remove=True
        )
        return
    except docker_errors.DockerException as e:
        logger.error("Something went wrong with docker!")
        raise docker_errors.DockerException(e)

def start_zap_service():
    import os
    from docker import from_env as docker_from_env, errors as docker_errors
    from loguru import logger
    logger.info("Starting ZAP service...")
    try:
        client = docker_from_env()
        try:
            existing = client.containers.get("restack_zaproxy")
            if existing.status == "running":
                existing.stop()
            existing.remove()
        except docker_errors.NotFound:
            pass
        client.containers.run(
            image="zaproxy/zap-weekly",
            name="restack_zaproxy",
            ports={"8090/tcp": 8090},
            environment={
                "ZAP_JAVA_OPTS": "-Xms512m -Xmx4g"
            },
            volumes={
                f"{os.getenv('ZAP_TEMPLATES')}": {
                    "bind": "/home/zap/.ZAP/plugin", # Only save plugins. Do not save any sessions, contexts, and other stuff.
                    "mode": "rw",
                }
            },
            command=[
                "zap.sh",
                "-daemon",
                "-host", "0.0.0.0",
                "-port", "8090",
                "-config", f"api.key={os.getenv('ZAP_API_KEY')}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=True",
                "-config", "selenium.firefoxDriver.path=/home/zap/.ZAP_D/webdriver/linux/64/geckodriver",
                "-config", "formhandler.enabled=true",
                "-config", "formhandler.submit=true",
                "-config", "formhandler.fields.field(0).field=.*",
                "-config", "formhandler.fields.field(0).value=test",
            ],
            detach=True,
            auto_remove=False,
        )
    except docker_errors.APIError:
        raise docker_errors.APIError
    except docker_errors.DockerException as e:
        raise docker_errors.DockerException(e)

def poll_zap_api() -> bool:
    import requests
    import os
    try:
        response = requests.get(
            "http://127.0.0.1:8090/JSON/core/view/version/", # The only that would change here later is the PORT
            headers={
                "X-ZAP-API-Key": os.getenv('ZAP_API_KEY')
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        return "version" in data
    except (requests.exceptions.RequestException, ValueError):
        return False

def wait_for_zap_or_crash():
    import os
    from time import sleep, monotonic
    from loguru import logger
    from zapv2 import ZAPv2
    logger.info("Checking if ZAP service is running...")
    TIMEOUT: float = 60.0
    POLL_INTERVAL: float = 5.0 # This should be aimed on low-end hardware
    deadline = monotonic() + TIMEOUT

    while monotonic() < deadline:
        if poll_zap_api():
            logger.info("ZAP API found!")
            logger.info("Updating zap...")
            zap_client = ZAPv2(apikey=os.getenv("ZAP_API_KEY"), proxies={"http": "http://127.0.0.1:8090"})
            if not zap_client.autoupdate.is_latest_version:
                logger.info("Zap out of date! Updating...")
                zap_client.autoupdate.download_latest_release()
                sleep(5)
            del zap_client # after an update request, this object should be destroyed
            ensure_zap_addons() # ensure that some addons are installed
            return
        sleep(POLL_INTERVAL)
    raise Exception("ZAP API could not be found! Polling timed out")

def stop_zap_service():
    from docker import from_env as docker_from_env
    from loguru import logger
    try:
        client = docker_from_env()
        zap_container = client.containers.get("restack_zaproxy")
        if zap_container.status == "running":
            zap_container.stop()
        zap_container.remove()
    except Exception as e:
        logger.error("Something went wrong with docker!")
        raise e

def zap_get_request(path, params=None, headers=None):
    import requests
    import os
    response = requests.get(
        f"http://127.0.0.1:8090/{path}",
        params=params or {},
        headers=headers or {
            "X-ZAP-API-Key": os.getenv('ZAP_API_KEY')
        },
        timeout=60
    )
    response.raise_for_status()
    return response.json()

def ensure_zap_addons():
    required_addons = [
        "packscanrules",
        "packpentester",
        "authhelper",
        "client",
        "sqliplugin",
    ]
    zap_get_request("/JSON/autoupdate/action/setOptionInstallAddonUpdates/", {"Boolean": "true"})
    zap_get_request("/JSON/autoupdate/action/setOptionInstallScannerRules/", {"Boolean": "true"})
    for addon_id in required_addons:
        zap_get_request("/JSON/autoupdate/action/installAddon/", {"id": addon_id})
    # log for successful update