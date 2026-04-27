from modules.interfaces.types.context import TechEntry


def read_required_images() -> list[str]:
    """
    Reads the required images from the docker_images file.
    :return: A list of image tags
    :raise: FileNotFoundError
    """
    from loguru import logger
    collection: list[str] = []
    try:
        with open("./app/config/docker/docker_images", "r") as f:
            for line in f.read().splitlines():
                collection.append(line)
    except FileNotFoundError:
        logger.exception("docker_images file not found!")
        raise FileNotFoundError
    return collection

def is_file_empty(path: str) -> bool:
    import os
    if os.path.getsize(path) == 0:
        return True
    return False

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

# misc

def list_to_str(items: list[str], separator: str = ",") -> str:
    """Converts a list of items into a string. The default separator of this is a comma (,)"""
    returnable: str = ""
    for index in range(len(items)):
        if index == len(items) - 1:
            returnable += items[index]
            break
        returnable += items[index] + separator
    return returnable

def tech_to_cpe(tech: list[TechEntry]) -> list[str]:
    """
    Converts a list of technologies into its cpe variant. This function follows CPE v2.3
    """
    # format: cpe:2.3:vendor:name:version:*:*:*:*:*:*:*
    cpe_list: list[str] = []
    for entry in tech:
        assert isinstance(entry, TechEntry)
        name = str(entry.name).lower().replace(" ", "_")
        version = "*"
        if entry.version != "":
            version = entry.version
        if entry.version is None:
            continue
        cpe_list.append(f"cpe:2.3:*:{name}:{version}:*:*:*:*:*:*:*")
    return cpe_list

def resolve_tech_to_tech_entry(tech: list[str | dict]) -> list[TechEntry]:
    """
    Converts a list of JSON stringified technologies into a list of TechEntry
    :param tech:
    :return:
    """
    assert tech is not None
    return [TechEntry.model_validate(entry) for entry in tech]

def compile_cpe_to_string(cpe_list: list[str]) -> str:
    """
    Compiles a list of CPEs into a singular string. The string output is white-space separated
    :param cpe_list:
    :return: the list in string format
    """
    string: str = ""
    for index in range(len(cpe_list)):
        if index == len(cpe_list) - 1:
            string += cpe_list[index]
            break
        string += cpe_list[index] + " "
    return string

def compile_tech_entry_to_string(arr: list[TechEntry]) -> list[str]:
    """
    Compiles a list of TechEntry into a list of stringified TechEntry.
    :param arr:
    :return:
    """
    assert arr is not None or arr != []
    temp = []
    for index in range(len(arr)):
        if index == len(arr) - 1:
            name = arr[index].name
            version = arr[index].version if arr[index].version else ""
            temp.append(str(name) + " " + str(version))

            break
        name = arr[index].name
        version = arr[index].version if arr[index].version else ""
        temp.append(str(name) + " " + str(version))
    return temp

def compile_and_parse_to_search_vuln_queriable(arr: list[TechEntry], command_list: list[str]) -> list[str]:
    """
    Compile an array of TechEntry into its stringified form, then append it to a passed command list
    :param arr: the array of TechEntry
    :param command_list: the command list to be modified
    :return: command list with the array of TechEntry appended to it
    """
    tech_list = compile_tech_entry_to_string(arr)
    assert tech_list is not None or tech_list != []
    for tech in tech_list:
        command_list.append("--query")
        command_list.append(tech)
    return command_list