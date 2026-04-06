"""MAC OUI vendor lookup and device type hinting."""

# Curated OUI prefix -> (vendor, device_type) mapping
# Prefix is first 3 octets, lowercase, colon-separated
# Covers common consumer/IoT devices found on home networks

OUI_DB: dict[str, tuple[str, str]] = {
    # Amazon
    "08:a6:bc": ("Amazon", "Smart Speaker/Display"),
    "00:f3:61": ("Amazon", "Smart Speaker/Display"),
    "b4:e4:54": ("Amazon", "Smart Speaker/Display"),
    "b0:73:9c": ("Amazon", "Smart Speaker/Display"),
    "e0:f7:28": ("Amazon", "Smart Speaker/Display"),
    "3c:5c:c4": ("Amazon", "Smart Speaker/Display"),
    "44:00:49": ("Amazon", "Smart Speaker/Display"),
    "fc:65:de": ("Amazon", "Smart Speaker/Display"),
    "cc:f7:35": ("Amazon", "Smart Speaker/Display"),
    "f0:f0:a4": ("Amazon", "Smart Speaker/Display"),
    "a4:08:ea": ("Amazon", "Smart Speaker/Display"),
    "68:54:fd": ("Amazon", "Smart Speaker/Display"),
    "40:a2:db": ("Amazon", "Smart Speaker/Display"),
    "74:c2:46": ("Amazon", "Smart Speaker/Display"),
    "38:f7:3d": ("Amazon", "Smart Speaker/Display"),
    "0c:47:c9": ("Amazon", "Smart Speaker/Display"),
    "84:d6:d0": ("Amazon", "Smart Speaker/Display"),
    "34:d2:70": ("Amazon", "Smart Speaker/Display"),
    "4c:ef:c0": ("Amazon", "Smart Speaker/Display"),
    "ac:63:be": ("Amazon", "Smart Speaker/Display"),
    "18:74:2e": ("Amazon", "Smart Speaker/Display"),
    "10:ce:a9": ("Amazon", "Smart Speaker/Display"),
    "14:91:82": ("Amazon", "Fire TV"),
    "78:e1:03": ("Amazon", "Kindle"),

    # Blink (Amazon)
    "74:ab:93": ("Blink", "Security Camera"),

    # Ring (Amazon)
    "5c:47:5e": ("Ring", "Doorbell/Camera"),
    "34:3e:a4": ("Ring", "Doorbell/Camera"),
    "50:dc:e7": ("Ring", "Doorbell/Camera"),

    # Apple
    "d0:03:4b": ("Apple", "iPhone/iPad/Mac"),
    "54:e6:1b": ("Apple", "iPhone/iPad/Mac"),
    "6c:4a:85": ("Apple", "iPhone/iPad/Mac"),
    "a8:51:ab": ("Apple", "iPhone/iPad/Mac"),
    "50:32:37": ("Apple", "iPhone/iPad/Mac"),
    "5c:e9:1e": ("Apple", "iPhone/iPad/Mac"),
    "a4:83:e7": ("Apple", "iPhone/iPad/Mac"),
    "f0:18:98": ("Apple", "iPhone/iPad/Mac"),
    "ac:bc:32": ("Apple", "iPhone/iPad/Mac"),
    "3c:06:30": ("Apple", "iPhone/iPad/Mac"),
    "14:98:77": ("Apple", "iPhone/iPad/Mac"),
    "28:6a:ba": ("Apple", "iPhone/iPad/Mac"),
    "c8:69:cd": ("Apple", "iPhone/iPad/Mac"),
    "f4:5c:89": ("Apple", "iPhone/iPad/Mac"),
    "a8:88:08": ("Apple", "iPhone/iPad/Mac"),
    "dc:a9:04": ("Apple", "iPhone/iPad/Mac"),
    "78:7b:8a": ("Apple", "iPhone/iPad/Mac"),
    "88:66:a5": ("Apple", "iPhone/iPad/Mac"),
    "a0:78:17": ("Apple", "iPhone/iPad/Mac"),
    "70:56:81": ("Apple", "Apple TV"),
    "c8:2a:14": ("Apple", "Apple TV"),
    "40:9c:28": ("Apple", "Apple TV"),
    "e0:b5:2d": ("Apple", "HomePod"),

    # Samsung
    "1c:e8:9e": ("Samsung", "Smart TV/Appliance"),
    "50:fd:d5": ("Samsung", "Smart TV/Appliance"),
    "8c:79:f5": ("Samsung", "Phone/Tablet"),
    "c0:97:27": ("Samsung", "Phone/Tablet"),
    "a8:7c:01": ("Samsung", "Phone/Tablet"),
    "10:30:47": ("Samsung", "Phone/Tablet"),
    "cc:3a:61": ("Samsung", "Phone/Tablet"),
    "78:47:1d": ("Samsung", "Phone/Tablet"),
    "90:18:7c": ("Samsung", "Phone/Tablet"),
    "b4:3a:28": ("Samsung", "Phone/Tablet"),
    "d0:87:e2": ("Samsung", "Smart TV"),
    "f8:3f:51": ("Samsung", "Smart TV"),
    "8c:71:f8": ("Samsung", "Smart TV"),
    "64:b5:c6": ("Samsung", "Smart TV"),

    # SmartThings (Samsung)
    "68:3a:48": ("SmartThings", "Smart Home Hub/Sensor"),
    "28:6d:97": ("SmartThings", "Smart Home Hub/Sensor"),
    "d0:52:a8": ("SmartThings", "Smart Home Hub/Sensor"),

    # Intel
    "cc:f9:e4": ("Intel", "PC/Laptop"),
    "6c:f6:da": ("Intel", "PC/Laptop"),
    "d4:54:8b": ("Intel", "PC/Laptop"),
    "60:e3:2b": ("Intel", "PC/Laptop"),
    "08:5b:d6": ("Intel", "PC/Laptop"),
    "48:51:b7": ("Intel", "PC/Laptop"),
    "80:86:f2": ("Intel", "PC/Laptop"),
    "34:13:e8": ("Intel", "PC/Laptop"),
    "a4:4c:c8": ("Intel", "PC/Laptop"),
    "b4:96:91": ("Intel", "PC/Laptop"),
    "a0:36:9f": ("Intel", "PC/Laptop"),
    "3c:58:c2": ("Intel", "PC/Laptop"),
    "9c:b6:d0": ("Intel", "PC/Laptop"),
    "00:15:5d": ("Microsoft", "Hyper-V VM"),

    # TP-Link
    "70:4f:57": ("TP-Link", "Smart Plug/Switch"),
    "ac:84:c6": ("TP-Link", "Smart Plug/Switch"),
    "60:32:b1": ("TP-Link", "Smart Plug/Switch"),
    "b0:95:75": ("TP-Link", "Smart Plug/Switch"),
    "98:da:c4": ("TP-Link", "Smart Plug/Switch"),
    "50:c7:bf": ("TP-Link", "Router/AP"),
    "c0:06:c3": ("TP-Link", "Router/AP"),
    "14:eb:b6": ("TP-Link", "Router/AP"),
    "30:de:4b": ("TP-Link", "Router/AP"),
    "5c:a6:e6": ("TP-Link", "Smart Plug/Switch"),
    "b4:b0:24": ("TP-Link", "Smart Plug/Switch"),
    "54:af:97": ("TP-Link", "Smart Plug/Switch"),

    # Google/Nest
    "f4:f5:d8": ("Google", "Chromecast/Nest"),
    "54:60:09": ("Google", "Chromecast/Nest"),
    "a4:77:33": ("Google", "Nest Hub/Speaker"),
    "48:d6:d5": ("Google", "Nest Thermostat"),
    "64:16:66": ("Google", "Nest Cam"),
    "18:b4:30": ("Google", "Nest/Chromecast"),

    # Tuya / Generic IoT
    "84:e3:42": ("Tuya", "Smart Plug/Bulb"),
    "d8:1f:12": ("Tuya", "Smart Plug/Bulb"),
    "a0:92:08": ("Tuya", "Smart Plug/Bulb"),
    "10:d5:61": ("Tuya", "Smart Plug/Bulb"),

    # Espressif (ESP32/ESP8266 IoT modules)
    "ac:0b:fb": ("Espressif", "IoT Device (ESP32)"),
    "24:6f:28": ("Espressif", "IoT Device (ESP32)"),
    "30:ae:a4": ("Espressif", "IoT Device (ESP32)"),
    "a4:cf:12": ("Espressif", "IoT Device (ESP32)"),
    "cc:50:e3": ("Espressif", "IoT Device (ESP32)"),
    "84:cc:a8": ("Espressif", "IoT Device (ESP8266)"),
    "bc:dd:c2": ("Espressif", "IoT Device (ESP32)"),
    "c4:4f:33": ("Espressif", "IoT Device (ESP32)"),

    # Raspberry Pi
    "e4:5f:01": ("Raspberry Pi", "Raspberry Pi"),
    "b8:27:eb": ("Raspberry Pi", "Raspberry Pi"),
    "dc:a6:32": ("Raspberry Pi", "Raspberry Pi"),
    "d8:3a:dd": ("Raspberry Pi", "Raspberry Pi"),
    "28:cd:c1": ("Raspberry Pi", "Raspberry Pi"),

    # Nintendo
    "98:e2:55": ("Nintendo", "Switch"),
    "a4:c0:e1": ("Nintendo", "Switch"),
    "58:bd:a3": ("Nintendo", "Switch"),
    "78:a2:a0": ("Nintendo", "Switch/Wii U"),
    "e8:4e:ce": ("Nintendo", "Switch"),
    "04:03:d6": ("Nintendo", "Switch"),

    # Sony PlayStation
    "00:d9:d1": ("Sony", "PlayStation"),
    "00:04:1f": ("Sony", "PlayStation"),
    "bc:60:a7": ("Sony", "PlayStation"),
    "f8:46:1c": ("Sony", "PlayStation"),
    "70:9e:29": ("Sony", "PlayStation"),
    "a8:e3:ee": ("Sony", "PlayStation"),

    # Microsoft Xbox
    "98:5f:d3": ("Microsoft", "Xbox"),
    "c8:3f:26": ("Microsoft", "Xbox"),
    "7c:ed:8d": ("Microsoft", "Xbox"),
    "60:45:bd": ("Microsoft", "Xbox"),

    # Roku
    "c0:d2:f3": ("Roku", "Streaming Player/TV"),
    "b0:a7:37": ("Roku", "Streaming Player/TV"),
    "ac:3a:7a": ("Roku", "Streaming Player/TV"),
    "d8:31:34": ("Roku", "Streaming Player/TV"),
    "84:ea:ed": ("Roku", "Streaming Player/TV"),

    # Sonos
    "b8:e9:37": ("Sonos", "Speaker"),
    "34:7e:5c": ("Sonos", "Speaker"),
    "48:a6:b8": ("Sonos", "Speaker"),
    "54:2a:1b": ("Sonos", "Speaker"),
    "78:28:ca": ("Sonos", "Speaker"),

    # Philips Hue
    "00:17:88": ("Philips Hue", "Smart Lighting Bridge"),
    "ec:b5:fa": ("Philips Hue", "Smart Lighting"),

    # Wyze
    "2c:aa:8e": ("Wyze", "Camera/Smart Home"),
    "a8:83:e0": ("Wyze", "Camera/Smart Home"),

    # Ecobee
    "44:61:32": ("ecobee", "Thermostat"),

    # Research Products Corp (Aprilaire)
    "b4:82:55": ("Aprilaire", "Thermostat/Humidifier"),

    # Murata (WiFi modules used in many devices)
    "58:d5:0a": ("Murata", "WiFi Module (Game Console/IoT)"),
    "44:91:60": ("Murata", "WiFi Module (Game Console/IoT)"),
    "f0:27:65": ("Murata", "WiFi Module (Game Console/IoT)"),

    # LG
    "a8:23:fe": ("LG", "Smart TV"),
    "c8:08:e9": ("LG", "Smart TV"),
    "74:40:be": ("LG", "Smart TV"),
    "58:fd:b1": ("LG", "Smart TV"),

    # Epson
    "f8:d0:27": ("Epson", "Printer"),
    "00:26:ab": ("Epson", "Printer"),

    # HP
    "c8:b5:b7": ("HP", "Printer"),
    "64:51:06": ("HP", "Printer"),
    "a0:d3:c1": ("HP", "Printer"),

    # Canon
    "c4:ac:59": ("Canon", "Printer"),
    "18:0c:ac": ("Canon", "Printer"),

    # Brother
    "00:80:77": ("Brother", "Printer"),
    "30:05:5c": ("Brother", "Printer"),

    # Ubiquiti
    "fc:ec:da": ("Ubiquiti", "Network Device"),
    "24:5a:4c": ("Ubiquiti", "Network Device"),
    "80:2a:a8": ("Ubiquiti", "Network Device"),
    "78:8a:20": ("Ubiquiti", "Network Device"),
    "f4:92:bf": ("Ubiquiti", "Network Device"),

    # Netgear
    "a4:2b:8c": ("Netgear", "Router/AP"),
    "6c:b0:ce": ("Netgear", "Router/AP"),
    "c4:04:15": ("Netgear", "Router/AP"),

    # Synology
    "00:11:32": ("Synology", "NAS"),

    # QNAP
    "24:5e:be": ("QNAP", "NAS"),

    # iRobot (Roomba)
    "50:14:79": ("iRobot", "Roomba"),

    # Wemo (Belkin)
    "58:ef:68": ("Wemo", "Smart Plug"),
    "c4:12:f5": ("Wemo", "Smart Plug"),
    "ec:1a:59": ("Belkin", "Smart Plug/Router"),

    # Chamberlain/MyQ
    "00:1d:c9": ("Chamberlain", "Garage Door Opener"),

    # Honeywell
    "00:d0:2d": ("Honeywell", "Thermostat"),
    "5c:f2:86": ("Honeywell", "Thermostat"),

    # Schlage/Allegion
    "00:1a:22": ("Schlage", "Smart Lock"),

    # August (Yale)
    "58:e2:8f": ("August", "Smart Lock"),

    # Withings
    "00:24:e4": ("Withings", "Smart Scale/Health"),

    # Peloton
    "a8:64:f1": ("Peloton", "Exercise Bike/Tread"),

    # Tesla
    "4c:fc:aa": ("Tesla", "Wall Connector/Powerwall"),

    # Gaoshengda (common WiFi module vendor)
    "64:e0:03": ("Gaoshengda", "WiFi Module (IoT)"),

    # Realtek (common in budget routers/adapters)
    "00:e0:4c": ("Realtek", "Network Adapter"),
    "48:e2:44": ("Realtek", "Network Adapter"),

    # Broadcom
    "20:10:7a": ("Broadcom", "Network Device"),
}


def _is_private_mac(mac: str) -> bool:
    """Check if MAC is locally administered (randomized/private Wi-Fi address)."""
    try:
        first_byte = int(mac[:2], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


# Full IEEE OUI database via mac-vendor-lookup (lazy init)
_mac_lookup = None


def _ieee_lookup(mac: str) -> str | None:
    """Look up vendor from full IEEE OUI database."""
    global _mac_lookup
    try:
        if _mac_lookup is None:
            from mac_vendor_lookup import MacLookup
            _mac_lookup = MacLookup()
        return _mac_lookup.lookup(mac)
    except Exception:
        return None


def lookup_vendor(mac: str) -> tuple[str | None, str | None]:
    """Look up vendor and device type from MAC address.

    Returns (vendor, device_type) or (None, None) if not found.
    Checks curated DB first (has device_type hints), then full IEEE DB.
    """
    prefix = mac.lower().strip()[:8]  # "aa:bb:cc"
    entry = OUI_DB.get(prefix)
    if entry:
        return entry
    if _is_private_mac(mac):
        return "Private Address", None
    # Fallback: full IEEE OUI database (vendor only, no device_type)
    vendor = _ieee_lookup(mac)
    if vendor:
        return vendor, None
    return None, None
