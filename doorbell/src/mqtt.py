import asyncio
import os
import re
import unicodedata
from ctypes import c_void_p, string_at
from typing import Any, Optional, TypedDict, cast
from config import AppConfig
from doorbell import DeviceType, Doorbell, Registry, sanitize_doorbell_name
from event import EventHandler
from paho.mqtt.client import MQTTMessage
from paho.mqtt import publish as mqtt_publish
from ha_mqtt_discoverable import Settings, DeviceInfo, Discoverable
from ha_mqtt_discoverable.sensors import BinarySensor, BinarySensorInfo, SensorInfo, Sensor, SwitchInfo, Switch, DeviceTrigger, DeviceTriggerInfo
from loguru import logger
# from home_assistant import sanitize_doorbell_name
from sdk.hcnetsdk import (NET_DVR_ALARMER,
                          NET_DVR_ALARMINFO_V30,
                          NET_DVR_VIDEO_INTERCOM_ALARM,
                          NET_DVR_VIDEO_INTERCOM_EVENT,
                          NET_DVR_ALARM_ISAPI_INFO,
                          NET_DVR_ACS_ALARM_INFO,
                          VIDEO_INTERCOM_ALARM_ALARMTYPE_DOOR_NOT_OPEN,
                          VIDEO_INTERCOM_EVENT_EVENTTYPE_UNLOCK_LOG,
                          VideoInterComAlarmType,
                          VideoInterComEventType,
                          UnlockType)
from sdk.acsalarminfo import (AcsAlarmInfoMajor, AcsAlarmInfoMajorAlarm, AcsAlarmInfoMajorException, AcsAlarmInfoMajorOperation, AcsAlarmInfoMajorEvent)
from typing_extensions import override
import xml.etree.ElementTree as ET
import json
import datetime
from dataclasses import dataclass
from pathlib import Path

from sdk.utils import SDKError

_current_mqtt_handler = None
_UNLOCK_EVENT_TYPE = "unlocked"
_RING_EVENT_TYPE = "ring"
_CALL_EVENT_TYPE = "call_completed"
_HOUSEHOLDER_PREFIX = "1001011"
_DEFAULT_CALL_STATE_POLL = 1
_ACTIVE_CALL_STATES = {"ring", "onCall"}


@dataclass
class ActiveCallSession:
    ring_started_at: datetime.datetime
    caller: Optional[str] = None
    ring_snapshot_path: Optional[str] = None
    ring_event_published: bool = False
    ring_seen: bool = False
    oncall_started_at: Optional[datetime.datetime] = None
    was_answered: bool = False
    unlock_performed: bool = False
    unlock_type: Optional[str] = None
    unlock_number: Optional[str] = None


def normalize_entity_object_id(name: str) -> str:
    if not name:
        return ""
    normalized = unicodedata.normalize("NFD", name.lower())
    normalized = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
    return normalized


def stable_event_device_key(doorbell: Doorbell, device: Optional[DeviceInfo] = None) -> str:
    if device is not None and getattr(device, "identifiers", None):
        key = normalize_entity_object_id(str(device.identifiers))
        if key:
            return key
    return normalize_entity_object_id(doorbell._config.name)


def event_entity_object_id(doorbell: Doorbell, suffix: str) -> str:
    slug = normalize_entity_object_id(doorbell._config.name)
    if not slug:
        slug = "hikvision"
    return f"event.{slug}_{suffix}"


def extract_device_info(doorbell: Doorbell) -> DeviceInfo:
    """Build and instance of DeviceInfo from the ISAPI /deviceinfo endpoint, if available, otherwise skip populating additional fields"""
    try:
        device_info = doorbell.get_device_info()
    except SDKError:
        # Cannot get device info using ISAPI, fallback to empty `device_info` XML element
        device_info = ET.Element("")

    # Dict to contain the extracted device information
    parsed_device_info: dict[str, Optional[str]] = {}
    model_element = device_info.find('{*}model')
    parsed_device_info["model"] = model_element.text if model_element is not None and model_element.text else None
    firmware_element = device_info.find('{*}firmwareVersion')
    parsed_device_info["firmware"] = firmware_element.text if firmware_element is not None and firmware_element.text else None
    hw_element = device_info.find('{*}hardwareVersion')
    parsed_device_info["hardware"] = hw_element.text if hw_element is not None and hw_element.text else None

    # Define the device struct
    return DeviceInfo(
        name=doorbell._config.name,
        identifiers=doorbell._device_info.serialNumber(),
        manufacturer="Hikvision",
        model=parsed_device_info["model"],
        sw_version=parsed_device_info["firmware"],
        hw_version=parsed_device_info["hardware"]
    )

class DeviceTriggerMetadata(TypedDict):
    """
    Helper dict class defining the information of a device trigger.
    Used when building the DeviceTrigger entity
    """
    name: str
    """Name of this device trigger"""
    type: str
    """Displayed in the HA UI"""
    subtype: str
    """Displayed in the HA UI"""
    payload: dict[str, str]
    """Optional payload sent in the trigger"""    

DEVICE_TRIGGERS_DEFINITIONS: dict[VideoInterComAlarmType, DeviceTriggerMetadata] = {
    VideoInterComAlarmType.TAMPERING_ALARM: DeviceTriggerMetadata(name='tampering_alarm', type='alarm', subtype='tampering'),
    VideoInterComAlarmType.HIJACKING_ALARM: DeviceTriggerMetadata(name='hijacking_alarm', type='alarm', subtype='hijacking'),
    VideoInterComAlarmType.MULTIPLE_PASSWORD_UNLOCK_FAILURE_ALARM: DeviceTriggerMetadata(name='multiple_passwords_unlock_failure', type='alarm', subtype='password unlock failures'),
    VideoInterComAlarmType.SOS: DeviceTriggerMetadata(name='sos', type='SOS', subtype=''),
    VideoInterComAlarmType.INTERCOM: DeviceTriggerMetadata(name='intercom', type='Intercom', subtype=''),
    VideoInterComAlarmType.SMART_LOCK_FINGERPRINT_ALARM: DeviceTriggerMetadata(name='smart_lock_fingerprint_alarm', type='smart lock alarm', subtype='fingerprint'),
    VideoInterComAlarmType.SMART_LOCK_PASSWORD_ALARM: DeviceTriggerMetadata(name='smart_lock_password_alarm', type='smart lock alarm', subtype='password'),
    VideoInterComAlarmType.SMART_LOCK_DOOR_PRYING_ALARM: DeviceTriggerMetadata(name='smart_lock_door_prying_alarm', type='smart lock alarm', subtype='door prying'),
    VideoInterComAlarmType.SMART_LOCK_DOOR_LOCK_ALARM: DeviceTriggerMetadata(name='smart_lock_door_lock_alarm', type='smart lock alarm', subtype='door lock'),
    VideoInterComAlarmType.SMART_LOCK_LOW_BATTERY_ALARM: DeviceTriggerMetadata(name='smart_lock_low_battery_alarm', type='smart lock alarm', subtype='low battery'),
    VideoInterComAlarmType.BLACKLIST_ALARM: DeviceTriggerMetadata(name='smart_lock_blacklist_alarm', type='alarm', subtype='blacklist'),
    VideoInterComAlarmType.SMART_LOCK_DISCONNECTED: DeviceTriggerMetadata(name='smart_lock_disconnected', type='smart lock disconnected', subtype=''),
    VideoInterComAlarmType.ACCESS_CONTROL_TAMPERING_ALARM: DeviceTriggerMetadata(name='access_control_tampering_alarm', type='alarm', subtype='access control tampering alarm'),
    VideoInterComAlarmType.SOS_CANCELLED: DeviceTriggerMetadata(name='sos_cancelled', type='alarm', subtype='sos cancelled'),
    VideoInterComAlarmType.NO_MASK_ALARM: DeviceTriggerMetadata(name='no_mask_alarm', type='alarm', subtype='no mask alarm'),
    VideoInterComAlarmType.FIRE_INPUT_ALARM: DeviceTriggerMetadata(name='fire_input_alarm', type='alarm', subtype='fire input alarm'),
    VideoInterComAlarmType.FIRE_INPUT_RESTORED: DeviceTriggerMetadata(name='fire_input_restored', type='alarm', subtype='fire input restored'),
    VideoInterComAlarmType.TOILET_ALARM: DeviceTriggerMetadata(name='toilet_alarm', type='alarm', subtype='toilet alarm'),
    VideoInterComAlarmType.TOILET_ALARM_CANCELLED: DeviceTriggerMetadata(name='toilet_alarm_cancelled', type='alarm', subtype='toilet alarm cancelled'),
    VideoInterComAlarmType.DRESSING_REMINDER: DeviceTriggerMetadata(name='dressing_reminder', type='alarm', subtype='dressing reminder'),
    VideoInterComAlarmType.FACE_TEMPERATURE_ALARM: DeviceTriggerMetadata(name='face_temperature_alarm', type='alarm', subtype='face temperature alarm'),
    VideoInterComAlarmType.DRESSING_REMINDER_CANCELLED: DeviceTriggerMetadata(name='dressing_reminder_cancelled', type='force', subtype='dressing reminder cancelled'),
}
"""Define the attributes of each DeviceTrigger entity, indexing them by the enum VideoInterComAlarmType"""

DEVICE_TRIGGERS_DEFINITIONS_EVENT: dict[VideoInterComEventType, DeviceTriggerMetadata] = {
    VideoInterComEventType.AUTHENTICATION_LOG: DeviceTriggerMetadata(name='authentication_log', type='event', subtype='authentication log'),
    VideoInterComEventType.ANNOUNCEMENT_READING_RECEIPT: DeviceTriggerMetadata(name='announcement_reading_receipt', type='event', subtype='announcement reading receipt'),
    VideoInterComEventType.UPLOAD_PLATE_INFO: DeviceTriggerMetadata(name='upload_plate_info', type='event', subtype='upload plate info'),
    VideoInterComEventType.DOOR_STATION_ISSUED_CARD_LOG: DeviceTriggerMetadata(name='door_station_issued_card_log', type='event', subtype='door station issued card log'),
    VideoInterComEventType.MASK_DETECT_EVENT: DeviceTriggerMetadata(name='mask_detect_event', type='event', subtype='mask detect event'),
}
"""Define the attributes of each DeviceTrigger entity, indexing them by the enum VideoInterComEventType"""

class MQTTHandler(EventHandler):
    name = 'MQTT'
    _sensors: dict[Doorbell, dict[str, Discoverable[Any]]] = {}
    """Keep references to the Discoverable entities created for each doorbell, indexed by their name"""

    def __init__(self, config: AppConfig.MQTT, doorbells: Registry) -> None:
        super().__init__()
        logger.info("Setting up event handler: {}", self.name)

        global _current_mqtt_handler
        _current_mqtt_handler = self

        # Initialize task storage at the start
        self._call_sensor_tasks: dict[Doorbell, asyncio.Task] = {}
        self._custom_event_device_discovery_topics: set[str] = set()
        self._event_discovery_state: dict[Doorbell, dict[str, bool]] = {}
        self._call_state_cache: dict[Doorbell, str] = {}
        self._active_call_sessions: dict[Doorbell, ActiveCallSession] = {}
        self._indoor_linked_outdoor_ip: dict[Doorbell, Optional[str]] = {}
        
        # Save the MQTT settings as an attribute
        self._mqtt_settings = Settings.MQTT(
            host=config.host,
            port=config.port,
            username=config.username,
            password=config.password
        )
        # Create the sensors for each doorbell:
        for doorbell in doorbells.values():

            logger.debug("Setting up entities for {}", doorbell._config.name)
            # Create an empty dict to hold the sensors
            self._sensors[doorbell] = {}
            doorbell_name = doorbell._config.name
            # Get the device information using ISAPI
            device = extract_device_info(doorbell)

            # Remove spaces and - from doorbell name
            sanitized_doorbell_name = sanitize_doorbell_name(doorbell_name)
            self._call_state_cache[doorbell] = "idle"
            self._event_discovery_state[doorbell] = {"unlock": False, "ring": False, "call": False}
            self._cleanup_legacy_debug_discovery(sanitized_doorbell_name)

            custom_events_enabled = self._custom_events_enabled(doorbell)
            logger.info("Resolved outdoor/custom events for {} (type={}): {}", doorbell._config.name, getattr(doorbell._type, "name", doorbell._type), custom_events_enabled)
            if custom_events_enabled:
                logger.info("Custom MQTT event entities enabled for {}", doorbell._config.name)
                self._ensure_custom_event_device_discovery(doorbell, device, sanitized_doorbell_name)

            if doorbell._type is not DeviceType.OUTDOOR:
                try:
                    self._indoor_linked_outdoor_ip[doorbell] = doorbell.get_outdoor_ip()
                except Exception as e:
                    logger.warning("Could not resolve linked outdoor IP for {}: {}", doorbell._config.name, e)
                    self._indoor_linked_outdoor_ip[doorbell] = None

            # No Callsensor for indoor
            # if not doorbell._type is DeviceType.INDOOR:
                
            ##################
            # Call state
            call_sensor_info = SensorInfo(
                name="Call state",
                unique_id=f"{device.identifiers}-call_state",
                device=device,
                default_entity_id=f"{sanitized_doorbell_name}_call_state",
                icon="mdi:bell")

            settings = Settings(mqtt=self._mqtt_settings, entity=call_sensor_info, manual_availability=True)
            call_sensor = Sensor(settings)
            call_sensor.set_state("idle")
            call_sensor.set_availability(True)
            self._sensors[doorbell]['call'] = call_sensor

            # Poll call state for all devices. If not configured, default to 1 second.
            call_state_poll_sec = doorbell._config.call_state_poll or _DEFAULT_CALL_STATE_POLL

            async def poll_call_sensor(d=doorbell, c=call_sensor):
                url = "/ISAPI/VideoIntercom/callStatus?format=json"
                requestBody = ""
                while True:
                    try:
                        logger.debug("Trying to get call status for doorbell: {} every {} sec", d._config.name, call_state_poll_sec)
                        response = d._call_isapi("GET", url, requestBody)
                        data = json.loads(response)

                        call_status_obj = data.get("CallStatus")
                        if call_status_obj:
                            call_state = call_status_obj.get("status")
                            if call_state:
                                previous_state = self._call_state_cache.get(d, "idle")
                                c.set_availability(True)
                                c.set_state(call_state)
                                self._call_state_cache[d] = call_state
                                await self._process_call_state_change(d, previous_state, call_state)
                                if previous_state != call_state:
                                    logger.info("Call sensor polling for : {} changed to {}", d._config.name, call_state)
                        else:
                            logger.warning("Unexpected ISAPI response from {}: {}", d._config.name, response)

                    except (SDKError, json.JSONDecodeError) as err:
                        logger.error("Communication error with {}: {}", d._config.name, err)
                        try:
                            c.set_availability(False)
                        except Exception:
                            pass
                    except Exception as e:
                        logger.exception("Unexpected error in polling loop: {}", e)
                        try:
                            c.set_availability(False)
                        except Exception:
                            pass

                    await asyncio.sleep(call_state_poll_sec)

            loop = asyncio.get_event_loop()
            self._call_sensor_tasks[doorbell] = loop.create_task(poll_call_sensor())

            ##################
            # Doors
            # Create switches for output relays used to open doors

            if not doorbell._type is DeviceType.INDOOR:
                num_doors = doorbell.get_num_outputs()
            else:
                num_doors = doorbell.get_num_outputs_indoor()
            logger.debug("Configuring {} door switches", num_doors)
            for door_id in range(num_doors):
                door_switch_info = SwitchInfo(
                    name=f"Door {door_id+1} relay",
                    unique_id=f"{device.identifiers}-door_relay_{door_id}",
                    device=device,
                    default_entity_id=f"{sanitized_doorbell_name}_door_relay_{door_id}")
                settings = Settings(mqtt=self._mqtt_settings, entity=door_switch_info, manual_availability=True)
                door_switch = Switch(settings, lambda client, _, message, d=doorbell, i=door_id: self.door_switch_callback(client, (d, i), message))
                door_switch.off()
                door_switch.set_availability(True)
                self._sensors[doorbell][f'door_{door_id}'] = door_switch

            ##################
            # Output ports
            # Create com1 and com2 ports for indoor stations

            if doorbell._type is DeviceType.INDOOR:
                
                num_coms = doorbell.get_num_coms_indoor()
                logger.debug("Configuring {} door switches", num_coms)
                for com_id in range(num_coms):
                    com_switch_info = SwitchInfo(
                        name=f"Com {com_id+1} relay",
                        unique_id=f"{device.identifiers}-com_relay_{com_id}",
                        device=device,
                        default_entity_id=f"{sanitized_doorbell_name}_com_relay_{com_id}")
                    settings = Settings(mqtt=self._mqtt_settings, entity=com_switch_info, manual_availability=True, assume_state=False)
                    # Change the lambda to capture doorbell and com_id as defaults
                    com_switch = Switch(settings, lambda client, _, message, d=doorbell, i=com_id: self.com_switch_callback(client, (d, i), message))
                    com_switch.off()
                    com_switch.set_availability(True)
                    self._sensors[doorbell][f'com_{com_id}'] = com_switch

    def _custom_events_enabled(self, doorbell: Doorbell) -> bool:
        configured = getattr(doorbell._config, "outdoor_events", None)
        if doorbell._type is DeviceType.OUTDOOR:
            return configured is not False
        return bool(configured)

    def _drop_none(self, value):
        if isinstance(value, dict):
            return {k: self._drop_none(v) for k, v in value.items() if v is not None}
        if isinstance(value, list):
            return [self._drop_none(v) for v in value if v is not None]
        return value

    def _mqtt_publish(self, topic: str, payload: str, retain: bool = False, qos: int = 0):
        auth: Optional[dict[str, str]] = None
        if self._mqtt_settings.username is not None:
            auth = {
                "username": self._mqtt_settings.username,
                "password": self._mqtt_settings.password or "",
            }

        try:
            if topic.startswith("homeassistant/event/"):
                logger.info("MQTT discovery publish -> topic={} retain={} payload={}", topic, retain, payload)
            mqtt_publish.single(
                topic=topic,
                payload=payload,
                qos=qos,
                retain=retain,
                hostname=self._mqtt_settings.host,
                port=self._mqtt_settings.port,
                auth=auth,
            )
        except Exception as e:
            logger.error("MQTT publish failed for topic {}: {}", topic, e)
            raise

    def _unlock_event_topics(self, doorbell: Doorbell) -> tuple[str, str]:
        return self._event_topics(doorbell, "unlock")

    def _republish_event_discovery(self, doorbell: Doorbell, event_key: str) -> None:
        self._ensure_custom_event_device_discovery(doorbell)


    def _unlock_event_topics(self, doorbell: Doorbell) -> tuple[str, str]:
        return self._event_topics(doorbell, "unlock")


    def _ring_event_topics(self, doorbell: Doorbell) -> tuple[str, str]:
        return self._event_topics(doorbell, "ring")


    def _call_event_topics(self, doorbell: Doorbell) -> tuple[str, str]:
        return self._event_topics(doorbell, "call")


    def _ensure_unlock_event_entity(
        self,
        doorbell: Doorbell,
        device: Optional[DeviceInfo] = None,
        sanitized_doorbell_name: Optional[str] = None,
    ) -> None:
        self._ensure_custom_event_device_discovery(doorbell, device, sanitized_doorbell_name)


    def _ensure_ring_event_entity(
        self,
        doorbell: Doorbell,
        device: Optional[DeviceInfo] = None,
        sanitized_doorbell_name: Optional[str] = None,
    ) -> None:
        self._ensure_custom_event_device_discovery(doorbell, device, sanitized_doorbell_name)


    def _ensure_call_event_entity(
        self,
        doorbell: Doorbell,
        device: Optional[DeviceInfo] = None,
        sanitized_doorbell_name: Optional[str] = None,
    ) -> None:
        self._ensure_custom_event_device_discovery(doorbell, device, sanitized_doorbell_name)


    def _cleanup_legacy_debug_discovery(self, sanitized_doorbell_name: str) -> None:
        legacy_topics = [
            f"homeassistant/sensor/{sanitized_doorbell_name}_manual_mqtt_debug/config",
            f"homeassistant/sensor/{sanitized_doorbell_name}_custom_events_debug/config",
        ]
        for topic in legacy_topics:
            try:
                self._mqtt_publish(topic, "", retain=True)
                logger.info("Cleared legacy MQTT discovery topic {}", topic)
            except Exception as e:
                logger.warning("Could not clear legacy MQTT discovery topic {}: {}", topic, e)

    def _custom_event_device_discovery_topic(self, doorbell: Doorbell, device: Optional[DeviceInfo] = None) -> str:
        return f"homeassistant/device/{stable_event_device_key(doorbell, device)}/config"


    def _ensure_custom_event_device_discovery(
        self,
        doorbell: Doorbell,
        device: Optional[DeviceInfo] = None,
        sanitized_doorbell_name: Optional[str] = None,
    ) -> None:
        if device is None:
            device = extract_device_info(doorbell)
        discovery_topic = self._custom_event_device_discovery_topic(doorbell, device)
        if discovery_topic in self._custom_event_device_discovery_topics:
            return

        if sanitized_doorbell_name is None:
            sanitized_doorbell_name = sanitize_doorbell_name(doorbell._config.name)

        payload = self._drop_none({
            "device": {
                "identifiers": [device.identifiers],
                "name": device.name,
                "manufacturer": device.manufacturer,
                "model": device.model,
                "sw_version": device.sw_version,
                "hw_version": device.hw_version,
            },
            "origin": {
                "name": "hikvision-doorbell-fork",
                "sw_version": "3.0.46",
            },
            "components": {
                "unlock_event": {
                    "platform": "event",
                    "name": f"{doorbell._config.name} Unlock",
                    "default_entity_id": event_entity_object_id(doorbell, "unlock"),
                    "unique_id": f"{device.identifiers}-unlock_event",
                    "state_topic": self._event_topics(doorbell, "unlock")[1],
                    "event_types": [_UNLOCK_EVENT_TYPE],
                    "icon": "mdi:door-open",
                },
                "ring_event": {
                    "platform": "event",
                    "name": f"{doorbell._config.name} Ring",
                    "default_entity_id": event_entity_object_id(doorbell, "ring"),
                    "unique_id": f"{device.identifiers}-ring_event",
                    "state_topic": self._event_topics(doorbell, "ring")[1],
                    "event_types": [_RING_EVENT_TYPE],
                    "icon": "mdi:bell-ring",
                    "device_class": "doorbell",
                },
                "call_event": {
                    "platform": "event",
                    "name": f"{doorbell._config.name} Call",
                    "default_entity_id": event_entity_object_id(doorbell, "call"),
                    "unique_id": f"{device.identifiers}-call_event",
                    "state_topic": self._event_topics(doorbell, "call")[1],
                    "event_types": [_CALL_EVENT_TYPE],
                    "icon": "mdi:phone-in-talk",
                },
            },
        })

        encoded_payload = json.dumps(payload, ensure_ascii=False)
        logger.info("Publishing custom event DEVICE discovery for {} to {} with payload {}", doorbell._config.name, discovery_topic, encoded_payload)
        self._mqtt_publish(discovery_topic, encoded_payload, retain=True)
        self._custom_event_device_discovery_topics.add(discovery_topic)
        self._event_discovery_state.setdefault(doorbell, {})["unlock"] = True
        self._event_discovery_state.setdefault(doorbell, {})["ring"] = True
        self._event_discovery_state.setdefault(doorbell, {})["call"] = True
        logger.info("Published custom event DEVICE discovery for {} to {}", doorbell._config.name, discovery_topic)

        loop = asyncio.get_event_loop()
        loop.call_later(10, lambda d=doorbell, k="device": self._republish_event_discovery(d, k))


    def _normalize_unlock_number(self, unlock_name: str, control_source_decoded: str) -> Optional[str]:
        raw_value = (control_source_decoded or "").strip()

        if unlock_name == "HOUSEHOLDER":
            prefix_index = raw_value.find(_HOUSEHOLDER_PREFIX)
            if prefix_index != -1:
                suffix = raw_value[prefix_index + len(_HOUSEHOLDER_PREFIX):]
                if suffix.isdigit() and suffix != "":
                    try:
                        return str(int(suffix))
                    except ValueError:
                        return raw_value
            return raw_value or None

        if unlock_name == "CENTER_PLATFORM":
            return None

        return raw_value or None

    def _save_unlock_event_image(self, doorbell: Doorbell, door_id: int, unlock_name: str, image_data: bytes) -> Optional[str]:
        if not image_data:
            return None

        try:
            base_path = Path("/media/hikvision") if os.path.isdir("/media") else Path.home() / "hikvision"
            output_dir = base_path / sanitize_doorbell_name(doorbell._config.name) / "unlock"
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"unlock_{timestamp}_door{door_id + 1}_{unlock_name.lower()}.jpg"
            file_path = output_dir / filename

            with open(file_path, "wb") as f:
                f.write(image_data)

            logger.info("Unlock event image saved: {}", file_path)

            try:
                from mqtt_input import get_mqtt_input

                mqtt_input = get_mqtt_input()
                if mqtt_input:
                    mqtt_input._last_snapshot_paths[doorbell] = str(file_path)
                    mqtt_input._publish_snapshot_image(doorbell, str(file_path))
                    logger.debug("Published unlock event image to snapshot entity for {}", doorbell._config.name)
            except Exception as e:
                logger.warning("Could not publish unlock image to MQTT image entity for {}: {}", doorbell._config.name, e)

            return str(file_path)
        except Exception as e:
            logger.error("Failed to save unlock event image for {}: {}", doorbell._config.name, e)
            return None

    def _save_ring_event_image(self, doorbell: Doorbell, image_data: bytes) -> Optional[str]:
        if not image_data:
            return None

        try:
            base_path = Path("/media/hikvision") if os.path.isdir("/media") else Path.home() / "hikvision"
            output_dir = base_path / sanitize_doorbell_name(doorbell._config.name) / "ring"
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            file_path = output_dir / f"ring_{timestamp}.jpg"
            with open(file_path, "wb") as f:
                f.write(image_data)

            logger.info("Ring event image saved: {}", file_path)
            try:
                from mqtt_input import get_mqtt_input

                mqtt_input = get_mqtt_input()
                if mqtt_input:
                    mqtt_input._last_snapshot_paths[doorbell] = str(file_path)
                    mqtt_input._publish_snapshot_image(doorbell, str(file_path))
            except Exception as e:
                logger.warning("Could not publish ring image to MQTT image entity for {}: {}", doorbell._config.name, e)
            return str(file_path)
        except Exception as e:
            logger.error("Failed to save ring event image for {}: {}", doorbell._config.name, e)
            return None

    def _capture_snapshot_for_ring(self, doorbell: Doorbell) -> Optional[str]:
        try:
            snapshot_path = doorbell.take_snapshot()
            if snapshot_path and os.path.exists(snapshot_path):
                with open(snapshot_path, "rb") as f:
                    return self._save_ring_event_image(doorbell, f.read())
            return snapshot_path
        except Exception as e:
            logger.error("Failed to capture ring snapshot for {}: {}", doorbell._config.name, e)
            return None

    def _normalize_caller_name(self, name: str) -> str:
        return (name or "").strip()

    def _format_caller_names(self, callers: list[str]) -> Optional[str]:
        if not callers:
            return None
        deduped = list(dict.fromkeys([caller for caller in callers if caller]))
        if not deduped:
            return None
        return ",".join(deduped)

    def _get_related_indoors(self, outdoor: Doorbell) -> list[Doorbell]:
        related = []
        for candidate, linked_ip in self._indoor_linked_outdoor_ip.items():
            if linked_ip and linked_ip == outdoor._config.ip:
                related.append(candidate)
        return related

    def _resolve_callers_for_outdoor(self, outdoor: Doorbell) -> list[str]:
        callers: list[str] = []
        for indoor in self._get_related_indoors(outdoor):
            state = self._call_state_cache.get(indoor, "idle")
            if state in _ACTIVE_CALL_STATES:
                callers.append(self._normalize_caller_name(indoor._config.name))
        return callers

    def publish_ring_event(
        self,
        doorbell: Doorbell,
        caller: Optional[str],
        image_path: Optional[str],
    ) -> None:
        self._ensure_ring_event_entity(doorbell)
        _, state_topic = self._ring_event_topics(doorbell)
        payload: dict[str, Any] = {"event_type": _RING_EVENT_TYPE}
        if caller:
            payload["caller"] = caller
        if image_path:
            payload["image_path"] = image_path
        self._mqtt_publish(state_topic, json.dumps(payload), retain=False)
        logger.info("Published ring event for {} to {} with payload {}", doorbell._config.name, state_topic, payload)

    def publish_call_event(
        self,
        doorbell: Doorbell,
        payload: dict[str, Any],
    ) -> None:
        self._ensure_call_event_entity(doorbell)
        _, state_topic = self._call_event_topics(doorbell)
        payload = {"event_type": _CALL_EVENT_TYPE, **payload}
        self._mqtt_publish(state_topic, json.dumps(payload), retain=False)
        logger.info("Published call event for {} to {} with payload {}", doorbell._config.name, state_topic, payload)

    async def _publish_ring_event_for_session(self, doorbell: Doorbell, session: ActiveCallSession) -> None:
        if session.ring_event_published or not session.ring_seen:
            return

        caller_names: list[str] = []
        for _ in range(3):
            caller_names = self._resolve_callers_for_outdoor(doorbell)
            if caller_names:
                break
            await asyncio.sleep(_DEFAULT_CALL_STATE_POLL)

        session.caller = self._format_caller_names(caller_names)

        loop = asyncio.get_running_loop()
        image_path = await loop.run_in_executor(None, self._capture_snapshot_for_ring, doorbell)
        if image_path:
            session.ring_snapshot_path = image_path

        self.publish_ring_event(doorbell, session.caller, session.ring_snapshot_path)
        session.ring_event_published = True

    async def _process_call_state_change(self, doorbell: Doorbell, previous_state: str, current_state: str) -> None:
        if self._custom_events_enabled(doorbell):
            session = self._active_call_sessions.get(doorbell)

            if previous_state == current_state:
                return

            now = datetime.datetime.now()

            if previous_state == "idle" and current_state == "ring":
                session = ActiveCallSession(ring_started_at=now, ring_seen=True)
                self._active_call_sessions[doorbell] = session
                asyncio.create_task(self._publish_ring_event_for_session(doorbell, session))
            elif previous_state == "idle" and current_state == "onCall":
                session = ActiveCallSession(ring_started_at=now)
                session.oncall_started_at = now
                session.was_answered = True
                self._active_call_sessions[doorbell] = session
                # Direct onCall: no ring event, but keep a snapshot for the final call event
                loop = asyncio.get_running_loop()
                image_path = await loop.run_in_executor(None, self._capture_snapshot_for_ring, doorbell)
                if image_path:
                    session.ring_snapshot_path = image_path
            elif session and previous_state == "ring" and current_state == "onCall" and session.oncall_started_at is None:
                session.oncall_started_at = now
                session.was_answered = True
            elif session and current_state == "ring" and not session.ring_seen:
                session.ring_seen = True
                asyncio.create_task(self._publish_ring_event_for_session(doorbell, session))

            session = self._active_call_sessions.get(doorbell)
            if session:
                caller_names = self._resolve_callers_for_outdoor(doorbell)
                formatted_callers = self._format_caller_names(caller_names)
                if formatted_callers:
                    session.caller = formatted_callers

                if current_state == "idle" and previous_state in _ACTIVE_CALL_STATES:
                    duration_base = session.oncall_started_at or session.ring_started_at
                    duration_seconds = max(0, int((datetime.datetime.now() - duration_base).total_seconds()))
                    result = "answered" if session.was_answered else "not_answered"
                    call_payload: dict[str, Any] = {
                        "result": result,
                        "duration": f"{duration_seconds}s",
                        "duration_seconds": duration_seconds,
                        "unlock_realizado": session.unlock_performed,
                        "had_ring": session.ring_seen,
                    }
                    if session.caller:
                        call_payload["caller"] = session.caller
                    if session.ring_snapshot_path:
                        call_payload["image_path"] = session.ring_snapshot_path
                    if session.unlock_performed:
                        call_payload["unlock_type"] = session.unlock_type
                        call_payload["unlock_number"] = session.unlock_number
                    self.publish_call_event(doorbell, call_payload)
                    self._active_call_sessions.pop(doorbell, None)

        else:
            for outdoor, session in self._active_call_sessions.items():
                caller_names = self._resolve_callers_for_outdoor(outdoor)
                formatted_callers = self._format_caller_names(caller_names)
                if formatted_callers:
                    session.caller = formatted_callers

    def publish_unlock_event(
        self,
        doorbell: Doorbell,
        door_id: int,
        unlock_name: str,
        control_source_decoded: str,
        image_path: Optional[str] = None,
    ) -> None:
        self._ensure_unlock_event_entity(doorbell)
        _, state_topic = self._unlock_event_topics(doorbell)
        normalized_number = self._normalize_unlock_number(unlock_name, control_source_decoded)
        payload = {
            "event_type": _UNLOCK_EVENT_TYPE,
            "unlock_type": unlock_name,
            "number": normalized_number,
            "door_id": door_id + 1,
        }
        if image_path:
            payload["image_path"] = image_path
        session = self._active_call_sessions.get(doorbell)
        if session:
            session.unlock_performed = True
            session.unlock_type = unlock_name
            session.unlock_number = normalized_number
        self._mqtt_publish(state_topic, json.dumps(payload), retain=False)
        logger.info("Published unlock event for {} to {} with payload {}", doorbell._config.name, state_topic, payload)

    def _event_topics(self, doorbell: Doorbell, event_key: str) -> tuple[str, str]:
        device = extract_device_info(doorbell)
        stable_key = stable_event_device_key(doorbell, device)
        discovery_topic = f"homeassistant/device/{stable_key}/config"
        state_topic = f"hikvision/{stable_key}/{event_key}/event"
        return discovery_topic, state_topic

    def com_switch_callback(self, client, user_data: tuple[Doorbell, int], message: MQTTMessage):
        doorbell, com_id = user_data
        command = message.payload.decode("utf-8")
        logger.debug("Received command: {}, com_id: {}, doorbell: {}", command, com_id, doorbell._config.name)
        match command:
            case "ON":
                doorbell.unlock_com(com_id)
            case "OFF":
                doorbell.lock_com(com_id)

    def door_switch_callback(self, client, user_data: tuple[Doorbell, int], message: MQTTMessage):
        doorbell, door_id = user_data
        command = message.payload.decode("utf-8")
        logger.debug("Received command: {}, door_id: {}, doorbell: {}", command, door_id, doorbell._config.name)
        match command:
            case "ON":
                doorbell.unlock_door(door_id)

    @override
    async def motion_detection(
            self,
            doorbell: Doorbell,
            command: int,
            device: NET_DVR_ALARMER,
            alarm_info: NET_DVR_ALARMINFO_V30,
            buffer_length,
            user_pointer: c_void_p):
        now = datetime.datetime.now()
        attributes = {'motion_detected': now.strftime("%Y-%m-%d %H:%M:%S")}
        metadata = DeviceTriggerMetadata(name="motion_detection", type="Motion detected", subtype="motion_detection", payload=attributes)
        self.handle_device_trigger(doorbell, metadata)

    @override
    async def acs_alarm(
            self,
            doorbell: Doorbell,
            command: int,
            device: NET_DVR_ALARMER,
            alarm_info: NET_DVR_ACS_ALARM_INFO,
            buffer_length,
            user_pointer: c_void_p):
        
        # Extract the type of alarm as a Python enum
        try:
            major = alarm_info.dwMajor
            minor = alarm_info.dwMinor
            door_id = alarm_info.struAcsEventInfo.dwDoorNo
            employee_id = alarm_info.struAcsEventInfo.dwEmployeeNo
            logger.debug("Access control event occured, trying to find the event for Major: {} : Minor: {}", major, minor)
            major_alarm = AcsAlarmInfoMajor(major)
            match major:
                case AcsAlarmInfoMajor.MAJOR_ALARM.value:
                    minor_alarm = AcsAlarmInfoMajorAlarm(minor)
                case AcsAlarmInfoMajor.MAJOR_EXCEPTION.value:
                    minor_alarm = AcsAlarmInfoMajorException(minor)
                case AcsAlarmInfoMajor.MAJOR_OPERATION.value:
                    minor_alarm = AcsAlarmInfoMajorOperation(minor)
                case AcsAlarmInfoMajor.MAJOR_EVENT.value:
                    minor_alarm = AcsAlarmInfoMajorEvent(minor)
            logger.info("Access control event: {} found with event: {}", major_alarm.name.lower(), minor_alarm.name.lower())
            match minor_alarm.name:
                case "MINOR_FACE_VERIFY_PASS":
                    logger.debug("Minor control event: {} found on door {} with employee id: {}", minor_alarm.name.lower(), door_id, employee_id)
                    attributes = {
                        'employee_id': employee_id,
                    }
                    trigger = DeviceTriggerMetadata(name=f"{major_alarm.name.lower()} {minor_alarm.name.lower()}", type=f"", subtype=f"{major_alarm.name.lower()} {minor_alarm.name.lower()}", payload=attributes)
                    self.handle_device_trigger(doorbell, trigger)
                case "MINOR_FINGERPRINT_COMPARE_PASS":
                    logger.debug("Minor control event: {} found on door {} with employee id: {}", minor_alarm.name.lower(), door_id, employee_id)
                    attributes = {
                        'employee_id': employee_id,
                    }
                    trigger = DeviceTriggerMetadata(name=f"{major_alarm.name.lower()} {minor_alarm.name.lower()}", type=f"", subtype=f"{major_alarm.name.lower()} {minor_alarm.name.lower()}", payload=attributes)
                    self.handle_device_trigger(doorbell, trigger)
                case _:
                    trigger = DeviceTriggerMetadata(name=f"{major_alarm.name.lower()} {minor_alarm.name.lower()}", type=f"", subtype=f"{major_alarm.name.lower()} {minor_alarm.name.lower()}")
                    self.handle_device_trigger(doorbell, trigger)
        except:
            logger.warning("Received unknown Access control event with Major: {} Minor: {}", major, minor)
            return

    @override
    async def isapi_alarm(
            self,
            doorbell: Doorbell,
            command: int,
            device: NET_DVR_ALARMER,
            alarm_info: NET_DVR_ALARM_ISAPI_INFO,
            buffer_length,
            user_pointer: c_void_p):
        
        if alarm_info.dwAlarmDataLen > 0:
            alarmData = alarm_info.pAlarmData.decode('utf-8', errors='ignore')
            data_type = "JSON" if alarm_info.byDataType == 1 else "XML"
            logger.info(f"Isapi alarm ({data_type}) from {doorbell._config.name}: with Alarm Data: {alarmData}") 
            try:
                parsed_json = json.loads(alarmData)
                event_name = parsed_json.get("eventType", "isapi_event")
            except Exception:
                event_name = "isapi_event"

            trigger = DeviceTriggerMetadata(name=f"ISAPI {event_name}", type="isapi_alarm", subtype=event_name, payload={"data": alarmData})
            self.handle_device_trigger(doorbell, trigger)
            
        else:
            # Handle empty data scenarios
            logger.warning(f"Isapi alarm received from {doorbell._config.name} but dwAlarmDataLen is 0")

    @override
    async def video_intercom_event(
            self,
            doorbell: Doorbell,
            command: int,
            device: NET_DVR_ALARMER,
            alarm_info: NET_DVR_VIDEO_INTERCOM_EVENT,
            buffer_length,
            user_pointer: c_void_p):

        async def update_door_entities(door_id: int, unlock_name: str, control_source_decoded: str, image_path: Optional[str]):
            """
            Helper function to update the relay switch of a given door and publish the unlock event.
            """
            logger.info("Door {} unlocked, updating relay switch and unlock event", door_id + 1)
            entity_id = f'door_{door_id}'
            door_sensor = cast(Switch, self._sensors[doorbell].get(entity_id))

            event_attributes = {
                'unlock_type': unlock_name,
                'number': self._normalize_unlock_number(unlock_name, control_source_decoded),
                'door_id': door_id + 1,
            }
            if image_path:
                event_attributes['image_path'] = image_path
            self.publish_unlock_event(doorbell, door_id, unlock_name, control_source_decoded, image_path=image_path)
            logger.debug("Published unlock event attributes {}", event_attributes)

            door_sensor.on()
            logger.debug("Doorbell updating relay switch {}", door_sensor)
            trigger = DeviceTriggerMetadata(name=f"Door unlocked", type="door open", subtype=f"door {door_id+1}", payload=event_attributes)
            self.handle_device_trigger(doorbell, trigger)

            # Wait some seconds, then turn off the switch entity (since the door relay in the doorbell is momentary)
            await asyncio.sleep(2)
            door_sensor.off()
            
        # Extract the type of event as a Python enum
        try:
            event_type = VideoInterComEventType(alarm_info.byEventType)
        except ValueError:
            logger.warning("Received unknown Event type: {}", alarm_info.byEventType)
            return
        
        match event_type:
            case VideoInterComEventType.UNLOCK_LOG:
                if not self._custom_events_enabled(doorbell):
                    logger.debug("Ignoring unlock log on device without custom events {}", doorbell._config.name)
                    return

                door_id = alarm_info.uEventInfo.struUnlockRecord.wLockID
                control_source_decoded = alarm_info.uEventInfo.struUnlockRecord.controlSource_decoded()
                unlock_type = alarm_info.uEventInfo.struUnlockRecord.byUnlockType

                try:
                    unlock_name = UnlockType(unlock_type).name
                    print(f"Unlock Method: {unlock_name}")
                except ValueError:
                    print(f"Unknown unlock type: {unlock_type}")
                    unlock_name = "Unknown"

                image_path = None
                image_len = int(alarm_info.uEventInfo.struUnlockRecord.dwPicDataLen)
                image_ptr = alarm_info.uEventInfo.struUnlockRecord.pImage
                if image_len > 0 and image_ptr:
                    try:
                        image_bytes = string_at(image_ptr, image_len)
                        image_path = self._save_unlock_event_image(doorbell, door_id, unlock_name, image_bytes)
                    except Exception as e:
                        logger.error("Failed to process unlock image for {}: {}", doorbell._config.name, e)

                # Name of the entity inside the dict array containing all the sensors
                entity_id = f'door_{door_id}'
                # Extract the sensor entity from the dict and cast to know type
                door_sensor = cast(Switch, self._sensors[doorbell].get(entity_id))
                # If the SDK returns a lock ID that is not starting from 0, 
                # we don't know what switch to update in HA -> trigger both of them
                # Make sure the switch is back in "OFF" position in case it was trigger by the switch
                if not door_sensor:
                    logger.warning("Received unknown lockID: {}", door_id)
                    # logger.debug("Changing switches back to OFF position")
                    num_doors = doorbell.get_num_outputs()
                    for door_id in range(num_doors):
                        await update_door_entities(door_id, unlock_name, control_source_decoded, image_path)
                    return
                await update_door_entities(door_id, unlock_name, control_source_decoded, image_path)

            case VideoInterComEventType.ILLEGAL_CARD_SWIPING_EVENT:
                control_source = alarm_info.uEventInfo.struUnlockRecord.controlSource()
                attributes = {
                    'control_source': control_source,
                }
                trigger = DeviceTriggerMetadata(name='illegal_card_swiping_event', type='event', subtype='illegal card_swiping event', payload=attributes)
                self.handle_device_trigger(doorbell, trigger)

            case VideoInterComEventType.MAGNETIC_DOOR_STATUS:
                door_id = alarm_info.uEventInfo.struUnlockRecord.wLockID
                logger.info("Magnetic door event detected on door {}", door_id + 1)
                attributes = {
                    'door_id': door_id + 1,
                }
                trigger = DeviceTriggerMetadata(name='magnetic door status', type='event', subtype='magnetic_door_status', payload=attributes)
                self.handle_device_trigger(doorbell, trigger)

            case _:
                """Generic event: create the device trigger entity according to the information inside the DEVICE_TRIGGERS_DEFINITIONS dict"""
                
                logger.info("Video intercom event {} detected on {}", event_type.name.lower(), doorbell._config.name)
                self.handle_device_trigger(doorbell, DEVICE_TRIGGERS_DEFINITIONS_EVENT[event_type])

    @override
    async def video_intercom_alarm(
            self,
            doorbell: Doorbell,
            command: int,
            device: NET_DVR_ALARMER,
            alarm_info: NET_DVR_VIDEO_INTERCOM_ALARM,
            buffer_length,
            user_pointer: c_void_p):
        
        # if not doorbell._type is DeviceType.INDOOR:
        call_sensor = cast(Sensor, self._sensors[doorbell]['call'])

        # Extract the type of alarm as a Python enum
        try:
            alarm_type = VideoInterComAlarmType(alarm_info.byAlarmType)
        except ValueError:
            logger.warning("Received unknown alarm type: {}", alarm_info.byAlarmType)
            return
        
        match alarm_type:
            case VideoInterComAlarmType.DOORBELL_RINGING:
                try:
                    button_pressed = alarm_info.wLockID + 1
                    raw_bytes = bytes(alarm_info.byDevNumber)
                    dev_number = raw_bytes.split(b'\x00')[0].decode('utf-8')
                except (UnicodeDecodeError, AttributeError, ValueError) as e:
                    dev_number = "unknown_device"
                    button_pressed = "unknown_button"
                    logger.error(f"Error decoding device numbers: {e}")
                logger.info("Doorbell ringing, button press from door: {} using button: {}, updating sensor", dev_number, button_pressed)
                logger.debug("Doorbell updating sensor {}", call_sensor)
                attributes = {
                    'device_number': dev_number,
                    'button_pressed': button_pressed
                }
                call_sensor.set_attributes(attributes)
                call_sensor.set_state('ring')
                previous_state = self._call_state_cache.get(doorbell, 'idle')
                self._call_state_cache[doorbell] = 'ring'
                await self._process_call_state_change(doorbell, previous_state, 'ring')
            case VideoInterComAlarmType.DISMISS_INCOMING_CALL:
                logger.info("Call dismissed, updating sensor")
                logger.debug("Doorbell updating sensor {}", call_sensor)
                previous_state = self._call_state_cache.get(doorbell, 'idle')
                call_sensor.set_state('idle')
                self._call_state_cache[doorbell] = 'idle'
                await self._process_call_state_change(doorbell, previous_state, 'idle')
            case VideoInterComAlarmType.ZONE_ALARM:
                #zone_name = str(alarm_info.uAlarmInfo.struZoneAlarm.byZoneName,'UTF-8')
                zone_type_id = alarm_info.uAlarmInfo.struZoneAlarm.byZoneType
                zone_number = alarm_info.uAlarmInfo.struZoneAlarm.dwZonendex
                match zone_type_id:
                    case 0:
                        zone_type= "Panic button"
                    case 1:
                        zone_type= "Door magnetic"
                    case 2:
                        zone_type= "Smoke detector"
                    case 3:
                        zone_type= "Active infrared"
                    case 4:
                        zone_type= "Passive infrared"
                    case 11:
                        zone_type= "Gas detector"
                    case 21:
                        zone_type= "Doorbell"                                                                                                 
                    case _:
                        zone_type= f"Unknown type {zone_type_id}"
                
                logger.info("Zone alarm detected on doorbell {}, zone type: {}, zone number: {} ", doorbell._config.name, zone_type, (zone_number+1))
                trigger = DeviceTriggerMetadata(name=f"Zone {zone_number+1}", type="alarm", subtype=f"alarm_{zone_number+1}")
                self.handle_device_trigger(doorbell, trigger)
            case VideoInterComAlarmType.DOOR_NOT_OPEN | VideoInterComAlarmType.DOOR_NOT_CLOSED:
                # Get information about the door that caused this alarm
                door_id = alarm_info.wLockID
                logger.info("Alarm {} detected on door {}", alarm_info.uAlarmInfo, door_id)
                
                # Create the key to extract the entity from the `sensors` dict, depending on the alarm type
                # use `subtype` to display doors starting from index 1 in the UI
                if alarm_info.byAlarmType == VIDEO_INTERCOM_ALARM_ALARMTYPE_DOOR_NOT_OPEN:
                    trigger = DeviceTriggerMetadata(name=f"door_not_open_{door_id}", type="not open", subtype=f"Door {door_id+1}")
                else:
                    trigger = DeviceTriggerMetadata(name=f"door_not_closed_{door_id}", type="not closed", subtype=f"Door {door_id+1}")

                self.handle_device_trigger(doorbell, trigger)
                
            case VideoInterComAlarmType.DOOR_OPEN_BY_EXTERNAL_FORCE:
                # Get information about the door that caused this alarm
                door_id = alarm_info.wLockID
                logger.info("External force detected on door {}", door_id + 1)
                attributes = {
                    'door_id': door_id + 1,
                }
                trigger = DeviceTriggerMetadata(name='door open by external force', type='event', subtype='door_open_by_external_force', payload=attributes)
                self.handle_device_trigger(doorbell, trigger)

            case _:
                """Generic alarm: create the device trigger entity according to the information inside the DEVICE_TRIGGERS_DEFINITIONS dict"""
                
                logger.info("Video intercom alarm {} detected on {}", alarm_type.name.lower(), doorbell._config.name)
                self.handle_device_trigger(doorbell, DEVICE_TRIGGERS_DEFINITIONS[alarm_type])

    @override
    async def unhandled_event(
            self,
            doorbell: Doorbell,
            command: int,
            device: NET_DVR_ALARMER,
            alarm_info_pointer,
            buffer_length,
            user_pointer: c_void_p):
        logger.warning("Unknown event from {}", doorbell._config.name)

    def handle_device_trigger(self, doorbell: Doorbell, trigger: DeviceTriggerMetadata):
        """
        Generate a device trigger event.
        Create the device trigger entity if it doesn't exist, and save it as part of the `sensors` dict
        """
        # Get the device trigger from the `sensors` dict, if it exists
        device_trigger = self._sensors[doorbell].get(trigger['name'])
        # If it doesn't exist, create it
        if not device_trigger:
            device_info = extract_device_info(doorbell)

            # This is the first time we encounter this alarm, first create the Python entity
            device_trigger_info = DeviceTriggerInfo(name=trigger['name'], 
                                                    device=device_info,
                                                    type=trigger['type'], 
                                                    subtype=trigger["subtype"],
                                                    unique_id=f"{device_info.identifiers}-{trigger['name']}")
            settings = Settings(mqtt=self._mqtt_settings, entity=device_trigger_info)
            device_trigger = DeviceTrigger(settings)
            # Save the entity in the dict for future reference
            self._sensors[doorbell][trigger["name"]] = device_trigger

        # Cast to know type DeviceTrigger
        device_trigger = cast(DeviceTrigger, device_trigger)
        # Trigger the event
        logger.info("Invoking device trigger automation{}", trigger)
        
        # Serialize the payload, if provided as part of the trigger
        json_payload = json.dumps(trigger['payload']) if trigger.get('payload') else None
        device_trigger.trigger(json_payload)

def get_mqtt_handler():
    """Get the current MQTTHandler instance"""
    global _current_mqtt_handler
    return _current_mqtt_handler