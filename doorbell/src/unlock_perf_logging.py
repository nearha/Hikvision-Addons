import time
from typing import Any

from loguru import logger


_INSTALLED = False


def install_unlock_perf_logging(MQTTHandler: Any) -> None:
    """Install lightweight unlock performance logging without changing unlock behavior."""
    global _INSTALLED
    if _INSTALLED or getattr(MQTTHandler, "_unlock_perf_logging_installed", False):
        return

    original_save_unlock_event_image = MQTTHandler._save_unlock_event_image
    original_publish_unlock_event = MQTTHandler.publish_unlock_event

    def _save_unlock_event_image_with_perf(self, doorbell, door_id, unlock_name, image_data):
        started_at = time.perf_counter()
        image_len = len(image_data) if image_data else 0
        image_path = None
        error = None

        try:
            image_path = original_save_unlock_event_image(self, doorbell, door_id, unlock_name, image_data)
            return image_path
        except Exception as exc:
            error = exc
            raise
        finally:
            total_ms = int((time.perf_counter() - started_at) * 1000)
            if not hasattr(self, "_unlock_perf_last_image"):
                self._unlock_perf_last_image = {}
            self._unlock_perf_last_image[(doorbell, door_id)] = {
                "image_len": image_len,
                "image_path": image_path,
                "image_total_ms": total_ms,
                "error": str(error) if error else None,
            }
            logger.info(
                "UNLOCK_PERF image_save device={} door_id={} unlock_type={} bytes={} path={} total_ms={} error={}",
                doorbell._config.name,
                door_id + 1,
                unlock_name,
                image_len,
                image_path,
                total_ms,
                error,
            )

    def _publish_unlock_event_with_perf(self, doorbell, door_id, unlock_name, control_source_decoded, image_path=None):
        started_at = time.perf_counter()
        try:
            return original_publish_unlock_event(
                self,
                doorbell,
                door_id,
                unlock_name,
                control_source_decoded,
                image_path=image_path,
            )
        finally:
            publish_ms = int((time.perf_counter() - started_at) * 1000)
            image_perf = None
            if hasattr(self, "_unlock_perf_last_image"):
                image_perf = self._unlock_perf_last_image.pop((doorbell, door_id), None)

            logger.info(
                "UNLOCK_PERF event_publish device={} door_id={} unlock_type={} number={} image_path={} publish_ms={} prior_image_total_ms={} prior_image_bytes={} prior_image_error={}",
                doorbell._config.name,
                door_id + 1,
                unlock_name,
                self._normalize_unlock_number(unlock_name, control_source_decoded),
                image_path,
                publish_ms,
                image_perf.get("image_total_ms") if image_perf else None,
                image_perf.get("image_len") if image_perf else None,
                image_perf.get("error") if image_perf else None,
            )

    MQTTHandler._save_unlock_event_image = _save_unlock_event_image_with_perf
    MQTTHandler.publish_unlock_event = _publish_unlock_event_with_perf
    MQTTHandler._unlock_perf_logging_installed = True
    _INSTALLED = True
    logger.info("UNLOCK_PERF logging installed")
