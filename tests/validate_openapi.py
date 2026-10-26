"""Basic YAML and local-reference check for the Go API OpenAPI document."""
from pathlib import Path
import sys

import yaml

document = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["openapi"].startswith("3.1.")
assert document["paths"]


def walk(value):
    if isinstance(value, dict):
        if "$ref" in value:
            reference = value["$ref"]
            assert reference.startswith("#/"), reference
            target = document
            for part in reference[2:].split("/"):
                target = target[part]
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)


walk(document)
print(f"OpenAPI YAML valid: {len(document['paths'])} paths, all local references resolve")
