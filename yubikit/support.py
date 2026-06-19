# Copyright (c) 2015-2022 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import ctypes
import logging
import sys
from dataclasses import replace

from smartcard.Exceptions import CardConnectionException

from .core import (
    PID,
    SEEDKEEPER,
    TRANSPORT,
    YUBIKEY,
    ApplicationNotAvailableError,
    CommandError,
    Connection,
    NotSupportedError,
    Version,
)
from .core.fido import FidoConnection
from .core.otp import OtpConnection
from .core.smartcard import (
    AID,
    ApduError,
    SmartCardConnection,
    SmartCardProtocol,
)
from .management import (
    CAPABILITY,
    DEVICE_FLAG,
    FORM_FACTOR,
    USB_INTERFACE,
    DeviceConfig,
    DeviceInfo,
    ManagementSession,
    Mode,
    VersionQualifier,
)
from .yubiotp import YubiOtpSession

logger = logging.getLogger(__name__)


# Old U2F AID, only used to detect the presence of the applet
_AID_U2F_YUBICO = bytes.fromhex("a0000005271002")

# Only used for pre YK4 devices, does not need to include any newer applets
_SCAN_APPLETS = (
    # OTP will be checked elsewhere and thus isn't needed here
    # FIDO is handled separately by _detect_fido_capabilities()
    (AID.PIV, CAPABILITY.PIV),
    (AID.OPENPGP, CAPABILITY.OPENPGP),
    (AID.OATH, CAPABILITY.OATH),
    (AID.SEEDKEEPER, CAPABILITY.SEEDKEEPER),
)

_BASE_NEO_APPS = CAPABILITY.OTP | CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP

# Firmware version reported for a Seedkeeper when CTAP2 does not expose one.
_FALLBACK_VERSION = Version(0, 1, 0)


def _read_ctap2_info(conn):
    """Read the CTAP2 Info from a FIDO or SmartCard connection, or None.

    A :class:`FidoConnection` is itself a CtapDevice; a SmartCardConnection is
    wrapped in :class:`SmartCardCtapDevice` so CTAP2 GetInfo can be issued over
    CCID. Returns ``None`` if the device does not support CTAP2.
    """
    try:
        from fido2.ctap2 import Ctap2

        if isinstance(conn, SmartCardConnection):
            from .core.fido import SmartCardCtapDevice

            device = SmartCardCtapDevice(conn)
        else:
            device = conn
        return Ctap2(device).info
    except Exception:
        logger.debug("Unable to read CTAP2 info", exc_info=True)
        return None


def _device_info_from_ctap2(info) -> DeviceInfo | None:
    """Build a Seedkeeper :class:`DeviceInfo` from a CTAP2 Info, or None.

    A Seedkeeper has no YubiKey Management applet (so the normal read fails) but
    does expose CTAP2. Building the info here, with the SEEDKEEPER capability,
    keeps it from being mislabeled as a YubiKey NEO by the version-3 fallbacks.
    Returns ``None`` if the CTAP2 device is not a Seedkeeper.
    """
    if info is None:
        return None

    # Prefer the firmware version reported by CTAP2 (CTAP 2.1+); the value is a
    # packed integer (major << 16 | minor << 8 | patch).
    fw = getattr(info, "firmware_version", None)
    if isinstance(fw, int) and fw > 0:
        version = Version((fw >> 16) & 0xFF, (fw >> 8) & 0xFF, fw & 0xFF)
    else:
        version = _FALLBACK_VERSION

    capabilities = CAPABILITY.FIDO2 | CAPABILITY.SEEDKEEPER
    logger.debug("Identified Seedkeeper over CTAP2, version %s", version)
    return DeviceInfo(
        config=DeviceConfig(
            enabled_capabilities={},  # Populated later
            auto_eject_timeout=0,
            challenge_response_timeout=0,
            device_flags=DEVICE_FLAG(0),
        ),
        serial=None,
        version=version,
        form_factor=FORM_FACTOR.UNKNOWN,
        supported_capabilities={TRANSPORT.USB: capabilities},
        is_locked=False,
        version_qualifier=VersionQualifier(version),
    )


def _detect_fido_capabilities(protocol: SmartCardProtocol) -> CAPABILITY:
    """Probe the FIDO applet to distinguish U2F-only from FIDO2 (CTAP2) devices."""
    try:
        protocol.select(AID.FIDO)
    except ApplicationNotAvailableError:
        # Fall back to old Yubico U2F AID
        try:
            protocol.select(_AID_U2F_YUBICO)
            return CAPABILITY.U2F
        except ApplicationNotAvailableError:
            return CAPABILITY(0)
    except CardConnectionException:
        # on windows, FIDO2 access requires admin rights
        if sys.platform == "win32" and not bool(ctypes.windll.shell32.IsUserAnAdmin()):
            logger.debug(
                "Failed to connect, on Windows admin rights are required!",
                exc_info=True,
            )
            return CAPABILITY.U2F | CAPABILITY.FIDO2
        return CAPABILITY(0)

    # AID.FIDO responded — at least U2F. Probe CTAP2 via GET_INFO (cmd 0x04).
    # APDU: NFCCTAP_MSG  CLA=0x80  INS=0x10  P1=0x80  P2=0x00  data=b"\x04"
    try:
        protocol.send_apdu(0x80, 0x10, 0x80, 0x00, b"\x04")
        return CAPABILITY.U2F | CAPABILITY.FIDO2  # SW 9000 — short response
    except ApduError as e:
        if e.sw == 0x9100:
            # SW 9100 = NFCCTAP_GETRESPONSE: response present but too long.
            # CTAP2 is supported; we don't need the full GET_INFO payload here.
            return CAPABILITY.U2F | CAPABILITY.FIDO2
    except Exception:
        logger.debug("CTAP2 not supported, falling back to U2F only", exc_info=True)

    return CAPABILITY.U2F  # GET_INFO failed — U2F only


def _read_info_ccid(conn, key_type, interfaces):
    version: Version | None = None
    try:
        mgmt = ManagementSession(conn)
        version = mgmt.version
        try:
            return mgmt.read_device_info()
        except NotSupportedError:
            if version.major == 3:
                # Workaround to "de-select" the Management Applet needed for NEO
                logger.debug("Send NEO de-select workaround...")
                conn.send_and_receive(b"\xa4\x04\x00\x08")
    except ApplicationNotAvailableError:
        logger.debug("Couldn't select Management application, use fallback")

    # Synthesize data
    capabilities = CAPABILITY(0)

    # Try to read serial (and version if needed) from OTP application
    serial = None
    try:
        otp = YubiOtpSession(conn)
        if version is None:
            version = otp.version
        try:
            serial = otp.get_serial()
        except Exception:
            logger.debug("Unable to read serial over OTP, no serial", exc_info=True)

        capabilities |= CAPABILITY.OTP
    except ApplicationNotAvailableError:
        logger.debug("Couldn't select OTP application, serial unknown")

    if version is None:
        logger.debug("Firmware version unknown, using 3.0.0 as a baseline")
        version = Version(3, 0, 0)  # Guess, no way to know

    # Scan for remaining capabilities
    logger.debug("Scan for available applications...")
    protocol = SmartCardProtocol(conn)
    fido_caps = _detect_fido_capabilities(protocol)
    if fido_caps:
        capabilities |= fido_caps
        logger.debug("Found FIDO capabilities: %s", fido_caps)
    for aid, code in _SCAN_APPLETS:
        try:
            protocol.select(aid)
            capabilities |= code
            logger.debug("Found applet: aid: %s, capability: %s", aid, code)
        except ApplicationNotAvailableError:
            logger.debug("Missing applet: aid: %s, capability: %s", aid, code)
        except Exception:
            logger.warning(
                "Error selecting aid: %s, capability: %s", aid, code, exc_info=True
            )

    # A non-YubiKey CTAP2 smartcard (e.g. Seedkeeper) reaches this fallback and
    # would otherwise be labeled a YubiKey NEO (the version-3 guess above). If it
    # exposes CTAP2, identify it and recover a real firmware version. Selecting
    # the SEEDKEEPER applet alone (via _SCAN_APPLETS) already sets the capability,
    # but CTAP2 also fixes the version.
    if (
        key_type is None
        and serial is None
        and capabilities & (CAPABILITY.FIDO2 | CAPABILITY.SEEDKEEPER)
    ):
        device_info = _device_info_from_ctap2(_read_ctap2_info(conn))
        if device_info is not None:
            version = device_info.version
            # capabilities |= CAPABILITY.SEEDKEEPER | CAPABILITY.FIDO2

    if not capabilities and not key_type:
        # NFC, no capabilities, probably not a YubiKey.
        raise ValueError("Device does not seem to be a YubiKey")

    # Assume U2F on devices >= 3.3.0
    if USB_INTERFACE.FIDO in interfaces or version >= (3, 3, 0):
        capabilities |= CAPABILITY.U2F

    return DeviceInfo(
        config=DeviceConfig(
            enabled_capabilities={},  # Populated later
            auto_eject_timeout=0,
            challenge_response_timeout=0,
            device_flags=DEVICE_FLAG(0),
        ),
        serial=serial,
        version=version,
        form_factor=FORM_FACTOR.UNKNOWN,
        supported_capabilities={
            TRANSPORT.USB: capabilities,
            TRANSPORT.NFC: capabilities,
        },
        is_locked=False,
        version_qualifier=VersionQualifier(version),
    )


def _read_info_otp(conn, key_type, interfaces):
    try:
        mgmt = ManagementSession(conn)
        return mgmt.read_device_info()
    except (ApplicationNotAvailableError, NotSupportedError):
        logger.debug("Unable to get info via Management application, use fallback")

    # Synthesize info
    otp = YubiOtpSession(conn)
    try:
        serial = otp.get_serial()
    except CommandError:
        logger.debug("Unable to read serial over OTP, no serial", exc_info=True)
        serial = None
    version = otp.version

    if key_type == YUBIKEY.NEO:
        usb_supported = _BASE_NEO_APPS
        if USB_INTERFACE.FIDO in interfaces or version >= (3, 3, 0):
            usb_supported |= CAPABILITY.U2F
        capabilities = {
            TRANSPORT.USB: usb_supported,
            TRANSPORT.NFC: usb_supported,
        }
    elif key_type == YUBIKEY.YKP:
        capabilities = {
            TRANSPORT.USB: CAPABILITY.OTP | CAPABILITY.U2F,
        }
    else:
        capabilities = {
            TRANSPORT.USB: CAPABILITY.OTP,
        }

    return DeviceInfo(
        config=DeviceConfig(
            enabled_capabilities={},  # Populated later
            auto_eject_timeout=0,
            challenge_response_timeout=0,
            device_flags=DEVICE_FLAG(0),
        ),
        serial=serial,
        version=version,
        form_factor=FORM_FACTOR.UNKNOWN,
        supported_capabilities=capabilities.copy(),
        is_locked=False,
        version_qualifier=VersionQualifier(version),
    )


def _read_info_ctap(conn, key_type, interfaces):
    try:
        mgmt = ManagementSession(conn)
        return mgmt.read_device_info()
    except Exception:  # SKY 1, NEO, YKP, or non-YubiKey FIDO2 smartcard (Seedkeeper)
        logger.debug("Unable to get info via Management application, use fallback")

        # A non-YubiKey CTAP2 smartcard (e.g. Seedkeeper) has no Management applet
        # but does expose CTAP2. Identify it before the YubiKey guesses below so it
        # is not mislabeled as a YubiKey NEO. key_type is None when there is no PID.
        if key_type is None:
            device_info = _device_info_from_ctap2(_read_ctap2_info(conn))
            if device_info is not None:
                return device_info

        # Best guess version
        if key_type == YUBIKEY.YKP:
            version = Version(4, 0, 0)
        else:
            version = Version(3, 0, 0)

        supported_apps = {TRANSPORT.USB: CAPABILITY.U2F}
        if key_type == YUBIKEY.NEO:
            supported_apps[TRANSPORT.USB] |= _BASE_NEO_APPS
            supported_apps[TRANSPORT.NFC] = supported_apps[TRANSPORT.USB]

        return DeviceInfo(
            config=DeviceConfig(
                enabled_capabilities={},  # Populated later
                auto_eject_timeout=0,
                challenge_response_timeout=0,
                device_flags=DEVICE_FLAG(0),
            ),
            serial=None,
            version=version,
            form_factor=FORM_FACTOR.USB_A_KEYCHAIN,
            supported_capabilities=supported_apps,
            is_locked=False,
            version_qualifier=VersionQualifier(version),
        )


def read_info(conn: Connection, pid: PID | None = None) -> DeviceInfo:
    """Reads out DeviceInfo from a YubiKey, or attempts to synthesize the data.

    Reading DeviceInfo from a ManagementSession is only supported for newer YubiKeys.
    This function attempts to read that information, but will fall back to gathering the
    data using other mechanisms if needed. It will also make adjustments to the data if
    required, for example to "fix" known bad values.

    The *pid* parameter must be provided whenever the YubiKey is connected via USB.

    :param conn: A connection to a YubiKey.
    :param pid: The USB Product ID.
    """
    logger.debug(f"Attempting to read device info, using {type(conn).__name__}")
    if pid:
        key_type: YUBIKEY | SEEDKEEPER | None = pid.yubikey_type
        interfaces = pid.usb_interfaces
    elif isinstance(conn, SmartCardConnection) and pid is None:
        # No PID: NFC connection or non-YubiKey contact reader
        key_type = None
        interfaces = USB_INTERFACE(0)  # Add interfaces later
        if conn.transport == TRANSPORT.NFC:
            # For NEO we need to figure out the mode, newer keys get it from Management
            protocol = SmartCardProtocol(conn)
            try:
                resp = protocol.select(AID.OTP)
                if resp[0] == 3 and len(resp) > 6:
                    interfaces = Mode.from_code(resp[6]).interfaces
            except ApplicationNotAvailableError:
                pass  # OTP turned off, this must be YK5, no problem
    else:
        raise ValueError("PID must be provided for non-NFC connections")

    if isinstance(conn, SmartCardConnection):
        info = _read_info_ccid(conn, key_type, interfaces)
    elif isinstance(conn, OtpConnection):
        info = _read_info_otp(conn, key_type, interfaces)
    elif isinstance(conn, FidoConnection):
        info = _read_info_ctap(conn, key_type, interfaces)
    else:
        raise TypeError("Invalid connection type")

    logger.debug("Read info: %s", info)

    # Set usb_enabled if missing (pre YubiKey 5)
    if (
        info.has_transport(TRANSPORT.USB)
        and TRANSPORT.USB not in info.config.enabled_capabilities
    ):
        usb_enabled = info.supported_capabilities[TRANSPORT.USB]
        if usb_enabled == (CAPABILITY.OTP | CAPABILITY.U2F | USB_INTERFACE.CCID):
            # YubiKey Edge, hide unusable CCID interface from supported
            # usb_enabled = CAPABILITY.OTP | CAPABILITY.U2F
            info.supported_capabilities = {
                TRANSPORT.USB: CAPABILITY.OTP | CAPABILITY.U2F
            }

        # No PID means a non-YubiKey contact reader: interfaces was never populated.
        # Infer USB interface flags from probed capabilities so the masking below
        # does not strip capabilities that were successfully detected.
        if pid is None and not interfaces:
            if usb_enabled & (CAPABILITY.U2F | CAPABILITY.FIDO2):
                interfaces |= USB_INTERFACE.FIDO
            if usb_enabled & (
                CAPABILITY.PIV
                | CAPABILITY.OATH
                | CAPABILITY.OPENPGP
                | CAPABILITY.HSMAUTH
                | CAPABILITY.SEEDKEEPER
            ):
                interfaces |= USB_INTERFACE.CCID
            if usb_enabled & CAPABILITY.OTP:
                interfaces |= USB_INTERFACE.OTP

        if USB_INTERFACE.OTP not in interfaces:
            usb_enabled &= ~CAPABILITY.OTP
        if USB_INTERFACE.FIDO not in interfaces:
            usb_enabled &= ~(CAPABILITY.U2F | CAPABILITY.FIDO2)
        if USB_INTERFACE.CCID not in interfaces:
            usb_enabled &= ~(
                USB_INTERFACE.CCID
                | CAPABILITY.OATH
                | CAPABILITY.OPENPGP
                | CAPABILITY.PIV
            )

        info.config.enabled_capabilities[TRANSPORT.USB] = usb_enabled

    # SKY identified by PID
    if key_type == YUBIKEY.SKY:
        info.is_sky = True

    # YK4-based FIPS version
    if (4, 4, 0) <= info.version < (4, 5, 0):
        info.is_fips = True

    # Fix NFC if needed
    if info.has_transport(TRANSPORT.NFC):
        # Set nfc_enabled if missing (pre YubiKey 5)
        if TRANSPORT.NFC not in info.config.enabled_capabilities:
            info.config.enabled_capabilities[TRANSPORT.NFC] = (
                info.supported_capabilities[TRANSPORT.NFC]
            )
        # Workaround for invalid configurations
        if info.form_factor in (
            FORM_FACTOR.USB_A_NANO,
            FORM_FACTOR.USB_C_NANO,
            FORM_FACTOR.USB_C_LIGHTNING,
        ) or (
            info.form_factor is FORM_FACTOR.USB_C_KEYCHAIN and info.version < (5, 2, 4)
        ):
            # Known to not have NFC, remove capabilities
            supported = dict(info.supported_capabilities)
            del supported[TRANSPORT.NFC]
            replace(info, supported_capabilities=supported)
            del info.config.enabled_capabilities[TRANSPORT.NFC]

    logger.debug("Device info, after tweaks: %s", info)
    return info


def _fido_only(capabilities):
    # Explicit list of non-FIDO capabilities, to prevent future capability additions
    # from breaking this check.
    return (
        capabilities
        & (
            CAPABILITY.OTP
            | CAPABILITY.OATH
            | CAPABILITY.PIV
            | CAPABILITY.OPENPGP
            | CAPABILITY.HSMAUTH
        )
        == 0
    ) and capabilities & (CAPABILITY.U2F | CAPABILITY.FIDO2) != 0


def _is_preview(version):
    _PREVIEW_RANGES = (
        ((5, 0, 0), (5, 1, 0)),
        ((5, 2, 0), (5, 2, 3)),
        ((5, 5, 0), (5, 5, 2)),
    )
    for start, end in _PREVIEW_RANGES:
        if start <= version < end:
            return True
    return False


def get_name(info: DeviceInfo, key_type: YUBIKEY | SEEDKEEPER | None) -> str:
    """Determine the product name of a YubiKey

    :param info: The device info.
    :param key_type: The YubiKey hardware platform.
    """
    usb_supported = info.supported_capabilities[TRANSPORT.USB]

    # Guess the key type (over NFC)
    if not key_type:
        if CAPABILITY.SEEDKEEPER in usb_supported:
            # Seedkeeper type
            if CAPABILITY.FIDO2 in usb_supported:
                key_type = SEEDKEEPER.PRO
            else:
                key_type = SEEDKEEPER.STD
        elif info.version[0] == 3:
            key_type = YUBIKEY.NEO
        elif info.serial is None and _fido_only(usb_supported):
            key_type = YUBIKEY.SKY if info.version < (5, 2, 8) else YUBIKEY.YK4
        else:
            key_type = YUBIKEY.YK4

    # Generic name based on key type alone
    device_name = key_type.value

    # Improved name based on configuration
    if key_type == YUBIKEY.SKY:
        if CAPABILITY.FIDO2 not in usb_supported:
            device_name = "FIDO U2F Security Key"  # SKY 1
        if info.has_transport(TRANSPORT.NFC):
            device_name = "Security Key NFC"
    elif key_type == YUBIKEY.YK4:
        major_version = info.version[0]
        if major_version < 4:
            if info.version[0] == 0:
                return f"YubiKey ({info.version})"
            else:
                return "YubiKey"
        elif major_version == 4:
            if info.is_fips:
                device_name = "YubiKey FIPS (4 Series)"
            elif usb_supported == CAPABILITY.OTP | CAPABILITY.U2F:
                device_name = "YubiKey Edge"
            else:
                device_name = "YubiKey 4"

        if _is_preview(info.version):
            device_name = "YubiKey Preview"
        elif info.version >= (5, 1, 0):
            # Dynamic name building for YK5
            is_nano = info.form_factor in (
                FORM_FACTOR.USB_A_NANO,
                FORM_FACTOR.USB_C_NANO,
            )
            is_bio = info._is_bio
            is_c = info.form_factor in (  # Does NOT include Ci
                FORM_FACTOR.USB_C_KEYCHAIN,
                FORM_FACTOR.USB_C_NANO,
                FORM_FACTOR.USB_C_BIO,
            )

            # Base name
            if info.is_sky:
                name_parts = ["Security Key"]
            else:
                name_parts = ["YubiKey"]
                if not is_bio:
                    name_parts.append("5")

            # Form factor additions
            if is_c:
                name_parts.append("C")
            elif info.form_factor == FORM_FACTOR.USB_C_LIGHTNING:
                name_parts.append("Ci")

            if is_nano:
                name_parts.append("Nano")
            elif info.has_transport(TRANSPORT.NFC):
                name_parts.append("NFC")
            elif info.form_factor == FORM_FACTOR.USB_A_KEYCHAIN:
                name_parts.append("A")  # Only for non-NFC A Keychain.
            elif is_bio:
                name_parts.append("Bio")

            # Extra suffixes
            if info.is_fips:
                name_parts.append("FIPS")
            elif is_bio:
                if _fido_only(usb_supported):
                    name_parts.append("- FIDO Edition")
                elif CAPABILITY.PIV in usb_supported:
                    name_parts.append("- Multi-protocol Edition")
            elif info.is_sky and info.serial:
                name_parts.append("- Enterprise Edition")
            elif info.pin_complexity and not info.is_sky:
                name_parts.append("- Enhanced PIN")

            # Combine parts into a name and make final adjustments
            device_name = " ".join(name_parts).replace("5 C", "5C").replace("5 A", "5A")

    return device_name
