import logging

from . import config

_LOGGER_NAME = "erecords_scraper"


def get_logger():
    return logging.getLogger(_LOGGER_NAME)


def setup_logging():
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logger = get_logger()
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(
        config.LOGS_DIR / "scraper.log", encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.propagate = False
    return logger