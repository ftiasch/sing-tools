import logging


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)1.1s%(asctime)s.%(msecs)03d %(process)d %(filename)s:%(lineno)d] %(message)s",  # noqa: E501
        datefmt="%Y%m%d %H:%M:%S",
    )
