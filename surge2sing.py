import json
import logging
import sys

from common import setup_logging


def main():
    setup_logging()
    domain, domain_suffix, domain_regex = [], [], []
    for line_ in sys.stdin.readlines():
        if line_.startswith("#"):
            continue
        tokens = line_.rstrip().split(",")
        if len(tokens) == 2:
            type_ = tokens[0]
            match type_:
                case "DOMAIN-SUFFIX":
                    domain_suffix.append(tokens[1])
                case _:
                    logging.warning("unknown type %s" % (type_))
        else:
            logging.warning("skipped line %s" % (line_.rstrip()))
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
