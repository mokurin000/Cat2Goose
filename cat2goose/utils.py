from sys import stderr

from cat2goose.model import GooseRule


def translate(
    group_set: set[str], rename_map: dict[str, str], rule: str
) -> GooseRule | None:
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

    group = rename_map.get(group, group)
    group_set.add(group)

    match rule_type.upper():
        case "DOMAIN":
            return GooseRule(
                rule_type="domain", content=f"full:{content}", target_group=group
            )
        case "DOMAIN-KEYWORD":
            return GooseRule(
                rule_type="domain", content=f"keyword:{content}", target_group=group
            )
        case "DOMAIN-SUFFIX":
            return GooseRule(
                rule_type="domain", content=f"suffix:{content}", target_group=group
            )
        case "IP-CIDR":
            return GooseRule(rule_type="dip", content=content, target_group=group)
        case "IP-CIDR6":
            return GooseRule(
                rule_type="dip", content=content.__repr__(), target_group=group
            )
        case "GEOIP":
            content = f"geoip:{content.lower()}"
            return GooseRule(rule_type="dip", content=content, target_group=group)

        # Impossible to goose
        case "PROCESS-NAME":
            return None
        case _:
            print(f"warn: unsupported schema {rule_type}", file=stderr)
            print(f"full line: {rule}", file=stderr)
            return None
