import logging
import os
from base64 import b64decode, b64encode
from urllib.parse import parse_qs, urlencode, urlparse, urlsplit, urlunparse

import dns.exception
import dns.rdatatype
import dns.resolver
import requests
from flask import Flask

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)1.1s%(asctime)s.%(msecs)03d %(process)d %(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y%m%d %H:%M:%S",
)


def get_sub() -> str:
    upstream = os.getenv("UPSTREAM")
    logging.info("UPSTREAM=%s" % (upstream))
    return requests.get(upstream).text


class Vless:
    @staticmethod
    def parse(vless_link):
        parsed_url = urlparse(vless_link)

        query_params = parse_qs(parsed_url.query)

        result = {
            "id": parsed_url.username,
            "address": parsed_url.hostname,
            "port": parsed_url.port,
            "encryption": query_params.get("encryption", [None])[0],
            "type": query_params.get("type", [None])[0],
            "header_type": query_params.get("headerType", [None])[0],
            "host": query_params.get("host", [None])[0],
            "path": query_params.get("path", [None])[0],
            "flow": query_params.get("flow", [None])[0],
            "security": query_params.get("security", [None])[0],
            "sni": query_params.get("sni", [None])[0],
            "service_name": query_params.get("serviceName", [None])[0],
            "mode": query_params.get("mode", [None])[0],
            "alpn": query_params.get("alpn", [None])[0],
            "remarks": parsed_url.fragment,
        }
        return result

    @staticmethod
    def dump(parsed_info):
        query_params = {
            "encryption": parsed_info["encryption"],
            "type": parsed_info["type"],
            "headerType": parsed_info["header_type"],
            "host": parsed_info["host"],
            "path": parsed_info["path"],
            "flow": parsed_info["flow"],
            "security": parsed_info["security"],
            "sni": parsed_info["sni"],
            "serviceName": parsed_info["service_name"],
            "mode": parsed_info["mode"],
            "alpn": parsed_info["alpn"],
        }

        query_string = urlencode(query_params)

        vless_link = urlunparse(
            (
                "vless",
                f"{parsed_info['id']}@{parsed_info['address']}:{parsed_info['port']}",
                "",
                "",
                query_string,
                parsed_info["remarks"],
            )
        )

        return vless_link


class Transformer:
    resolver: dns.resolver.Resolver

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        nameserver = os.getenv("DNS", "223.5.5.5")
        logging.info("DNS=%s" % (nameserver))
        self.resolver.nameservers = [nameserver]

    def resolve(self, host: str) -> str:
        try:
            logging.info("DNS query|%s" % (host))
            answers = self.resolver.resolve(
                host,
                rdtype=dns.rdatatype.A,
                tcp=True,
                raise_on_no_answer=False,
            )
            if not answers:
                logging.info("DNS no A answers")
                answers = self.resolver.resolve(
                    host,
                    rdtype=dns.rdatatype.AAAA,
                    tcp=True,
                    raise_on_no_answer=True,
                )
            answer = answers[0].to_text()
            logging.info("DNS answer|%s" % (answer))
            return answer
        except dns.exception.DNSException:
            logging.exception("DNS error")
            return host

    def transform(self, share_link):
        """
        https://github.com/liolok/liolok.com/blob/master/v2ray-subscription-parse/index.md
        """
        match urlsplit(share_link).scheme:
            case "vless":
                vless = Vless.parse(share_link)
                vless["address"] = self.resolve(vless["address"])
                return Vless.dump(vless)
            case _:
                logging.warning("unknown proto|%s" % (share_link))
                return share_link


app = Flask(__name__)


def work():
    sub_raw = get_sub()
    tf = Transformer()
    return b64encode(
        "\n".join(
            map(tf.transform, b64decode(sub_raw).decode("utf-8").splitlines())
        ).encode("utf-8")
    )


@app.route("/")
def home():
    return work()
