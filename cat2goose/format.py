from collections.abc import Iterable

from cat2goose.model import GooseRule


def fewest_lines(goose_rules: Iterable[GooseRule]):
    result = ""

    goose_groups: dict[tuple[str, str], set[str]] = {}
    for goose_rule in goose_rules:
        group_key = (goose_rule.rule_type, goose_rule.target_group)
        goose_groups[group_key] = goose_groups.get(group_key, set())
        goose_groups[group_key].add(goose_rule.content)

    for (rule_type, target_group), contents in goose_groups.items():
        content = ", ".join(sorted(contents))
        result += f"{rule_type}({content}) -> {target_group}\n"

    return result


def absolute_semantic(goose_rules: Iterable[GooseRule]):
    result = ""

    last_rule = None

    for rule in goose_rules:
        group_key = (rule.rule_type, rule.target_group)

        match last_rule:
            case None:
                result += f"{rule.rule_type}("
            case _ if last_rule == group_key:
                result += ", "
            case _:
                result += f") -> {last_rule[1]}\n{rule.rule_type}("

        last_rule = group_key

        result += f"{rule.content}"

    result += f") -> {last_rule[1]}\n"

    return result
