import yaml

from sys import argv, stderr
from functools import partial

DEFAULT_OUTBOUNDS = ["direct", "block"]


def translate(group_set: set[str], rule: str) -> str | None:
    if rule.startswith("MATCH"):
        return None

    try:
        rule_type, content, group = rule.split(",")[:3]
    except ValueError:
        print(f"failed to parse {rule}", file=stderr)
        raise

    group_lower = group.lower()

    if "direct" in group_lower:
        group = "direct"
    elif "proxy" in group_lower or "proxies" in group_lower:
        group = "proxy"
    elif "reject" in group_lower:
        group = "block"

    group_set.add(group)

    match rule_type.upper():
        case "DOMAIN":
            return f"domain(full: {content}) -> {group}"
        case "DOMAIN-KEYWORD":
            return f"domain(keyword: {content}) -> {group}"
        case "DOMAIN-SUFFIX":
            return f"domain(suffix: {content}) -> {group}"
        case "IP-CIDR":
            return f"dip({content}) -> {group}"
        case "IP-CIDR6":
            return f'dip("{content}") -> {group}'
        case "GEOIP":
            return f"dip(geoip:{content.lower()}) -> {group}"

        # Impossible to goose
        case "PROCESS-NAME":
            return None
        case _:
            print(f"warn: unsupported schema {rule_type}", file=stderr)
            print(f"full line: {rule}", file=stderr)
            return None


def main():
    yaml_path = argv[1]
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.load(f, Loader=yaml.Loader)

    groups = set()

    if "rules" not in data:
        print("'rules' not found!", file=stderr)
        return

    print(
        "\n".join(
            filter(
                lambda line: line is not None,
                map(partial(translate, groups), data["rules"]),
            )
        )
    )

    groups = sorted(group for group in groups if group not in DEFAULT_OUTBOUNDS)

    if groups:
        groups = ", ".join(sorted(groups))
        print(f"# groups: {groups}")


if __name__ == "__main__":
    main()
