try:
    from mqtt import MQTTHandler
    from unlock_perf_logging import install_unlock_perf_logging

    install_unlock_perf_logging(MQTTHandler)
except Exception as exc:
    try:
        from loguru import logger

        logger.warning("UNLOCK_PERF logging could not be installed: {}", exc)
    except Exception:
        pass
