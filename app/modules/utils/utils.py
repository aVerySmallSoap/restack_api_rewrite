from typing import TextIO

from app.modules.interfaces.types.context import TechEntry


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

#noinspection D
def text_io_to_dict_list(text: TextIO, strict: bool) -> list[dict]:
    """
       Extract JSON objects from a text stream.

       The stream does not need to be one valid JSON document. It may contain:
       - JSONL objects
       - multiple adjacent JSON objects
       - blank lines
       - scanner noise before/between objects
       - NUL padding bytes decoded as "\\x00"

       Only top-level JSON objects are extracted. Top-level arrays are ignored.

       :param text: Text stream to parse.
       :param strict: If True, raise JSONDecodeError on malformed extracted objects
                      or trailing incomplete JSON. If False, skip bad/trailing data.
       :return: list of dictionaries.
       """
    from json import JSONDecodeError, loads as json_loads
    from loguru import logger
    stack: list[str] = []
    json_items: list[dict] = []

    buffer: list[str] = []
    in_string = False
    escaped = False
    object_start_offset: int | None = None
    absolute_offset = 0

    def reset_object_state() -> None:
        nonlocal buffer, stack, in_string, escaped, object_start_offset
        buffer = []
        stack = []
        in_string = False
        escaped = False
        object_start_offset = None

    for char in text.read():
        absolute_offset += 1

        # Ignore NUL bytes outside JSON objects. These showed up in your Nuclei file.
        if not stack and char == "\x00":
            continue

        # Ignore everything until a JSON object begins.
        if not stack:
            if char != "{":
                continue

            stack.append("{")
            buffer = ["{"]
            object_start_offset = absolute_offset - 1
            continue

        # From here on, we are inside a JSON object.
        buffer.append(char)

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "\"":
                in_string = False
            continue

        if char == "\"":
            in_string = True
            continue

        if char == "{":
            stack.append("{")
            continue

        if char == "}":
            stack.pop()

            if not stack:
                object_text = "".join(buffer)

                try:
                    parsed = json_loads(object_text)
                except JSONDecodeError:
                    logger.exception(
                        "Invalid JSON object detected at offset {}. Preview: {!r}",
                        object_start_offset,
                        object_text[:300],
                    )
                    reset_object_state()

                    if strict:
                        raise

                    continue

                if isinstance(parsed, dict):
                    json_items.append(parsed)
                else:
                    logger.warning(
                        "Skipping non-dict JSON value at offset {}: {}",
                        object_start_offset,
                        type(parsed).__name__,
                    )

                reset_object_state()

    # If the stream ended while inside an object.
    if stack:
        trailing = "".join(buffer)
        message = "Incomplete JSON object at end of stream"

        logger.warning("{} starting at offset {}. Preview: {!r}", message, object_start_offset, trailing[:300])

        if strict:
            raise JSONDecodeError(message, trailing, max(len(trailing) - 1, 0))

    return json_items

def list_to_str(items: list, separator: str = ",") -> str:
    """
    Converts a list of items into a string. The default separator of this is a comma (,)
    """
    _last_index = len(items) - 1
    _returnable: str = ""
    for index in range(len(items)):
        if index == _last_index:
            _returnable += items[index]
            break
        _returnable += items[index] + separator
    return _returnable

def set_to_str(items: set, separator: str = ",") -> str:
    """
    Converts a set of items into a string. The default separator of this is a comma (,)
    """
    _last_index = len(items) - 1
    _returnable: str = ""
    for index, item in enumerate(items):
        if index == _last_index:
            _returnable += str(item)
            break
        _returnable += str(item) + ","
    return _returnable

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