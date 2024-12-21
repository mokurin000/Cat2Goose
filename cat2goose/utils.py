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
        # domain-related
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
        case "DOMAIN-REGEX":
            return GooseRule(
                rule_type="domain", content=f"regex:'{content}'", target_group=group
            )

        # source IP
        case "SRC-IP-CIDR":
            return GooseRule(rule_type="sip", content=content, target_group=group)
        # destination IP
        case "IP-CIDR":
            return GooseRule(rule_type="dip", content=content, target_group=group)
        case "IP-CIDR6":
            return GooseRule(
                rule_type="dip", content=f"'{content}'", target_group=group
            )

        # geoip/geosite
        case "SRC-GEOIP":
            content = f"geoip:{content.lower()}"
            return GooseRule(rule_type="sip", content=content, target_group=group)
        case "GEOIP":
            content = f"geoip:{content.lower()}"
            return GooseRule(rule_type="dip", content=content, target_group=group)
        case "GEOSITE":
            content = f"geosite:{content.lower()}"
            return GooseRule(rule_type="domain", content=content, target_group=group)

        # source port
        case "SRC-PORT":
            content = content.replace("/", ",").replace(",", ", ")
            return GooseRule(rule_type="sport", content=content, target_group=group)
        # destination port
        case "DST-PORT":
            return GooseRule(rule_type="dport", content=content, target_group=group)

        # (match DSCP; is useful for BT bypass). See https://github.com/daeuniverse/dae/discussions/295
        case "DSCP":
            return GooseRule(rule_type="dscp", content=content, target_group=group)

        case "PROCESS-NAME":
            if group == "direct":
                group = "must_direct"
            return GooseRule(rule_type="pname", content=content, target_group=group)

        case _:
            print(f"warn: unsupported schema {rule_type}", file=stderr)
            print(f"full line: {rule}", file=stderr)
            return None
