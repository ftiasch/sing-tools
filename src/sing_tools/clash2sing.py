import json
import logging
import sys


def main():
    domain, domain_suffix, domain_regex = [], [], []
    for line_ in sys.stdin.readlines():
        tokens = line_.rstrip().split(":")
        if len(tokens) == 1:
            domain_suffix.append(tokens[0])
        else:
            type_ = tokens[0]
            match type_:
                case "full":
                    domain.append(tokens[1])
                case "regexp":
                    domain_regex.append(tokens[1])
                case _:
                    logging.warning("unknown type %s" % (type_))
    rules = []
    if domain:
        rules.append({"domain": domain})
    if domain_suffix:
        rules.append({"domain_suffix": domain_suffix})
    if domain_regex:
        rules.append({"domain_regex": domain_suffix})
    print(json.dumps({"version": 1, "rules": rules}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
