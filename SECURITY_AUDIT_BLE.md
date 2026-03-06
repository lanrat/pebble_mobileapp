# Bluetooth Security Audit: Pebble Mobile App

**Date:** 2026-03-06
**Scope:** Bluetooth/BLE communication security between the Pebble mobile app (Android/iOS) and Pebble smartwatches
**Repository:** `pebble_mobileapp` (Kotlin Multiplatform — libpebble3)

---

## Executive Summary

The Pebble mobile app relies **entirely on BLE link-layer encryption** for security. There is **no application-layer encryption, authentication, or integrity checking** on any protocol messages. The custom PPoG (Pebble Protocol over GATT) protocol and all 25+ Pebble protocol endpoints transmit data in plaintext above the BLE link layer. On iOS, the GATT server characteristics are configured **without encryption permissions**, making the attack surface significantly wider than on Android.

### Threat Model Answered

| Scenario | Risk | Details |
|----------|------|---------|
| **Passive sniffing** (paired connection) | **MEDIUM-HIGH** | If attacker captures BLE pairing exchange or breaks link encryption, ALL data is readable — notifications, calls, calendar, voice, music, health |
| **Active MITM** | **HIGH** | No mutual authentication — attacker can impersonate the watch, receive all notification data, and send commands (answer calls, control music) |
| **Watch out of range / absent** | **HIGH** | Attacker can impersonate the watch. Phone has no cryptographic way to distinguish real watch from fake |
| **Read phone information** | **HIGH** (with MITM) | Attacker receives notifications (SMS, email, WhatsApp, etc.), caller ID, calendar events with attendees/locations, music metadata, health data |
| **Reply to notifications / send voice** | **HIGH** (with MITM) | Attacker can send PhoneControl.Answer to answer calls, send canned replies, and inject dictation results |
| **Influence the phone** | **HIGH** (with MITM) | Phone executes watch commands without additional auth: answer/hang up calls, control music playback, trigger notification actions |

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Encryption & Authentication Analysis](#2-encryption--authentication-analysis)
3. [Attack Scenario: Passive Eavesdropping](#3-attack-scenario-passive-eavesdropping)
4. [Attack Scenario: Active MITM](#4-attack-scenario-active-mitm)
5. [Attack Scenario: Watch Absent / Out of Range](#5-attack-scenario-watch-absent--out-of-range)
6. [Data Exposure Inventory](#6-data-exposure-inventory)
7. [Phone Influence / Command Injection](#7-phone-influence--command-injection)
8. [Platform-Specific Vulnerabilities](#8-platform-specific-vulnerabilities)
9. [Protocol-Level Vulnerabilities](#9-protocol-level-vulnerabilities)
10. [Additional Attack Vectors](#10-additional-attack-vectors)
11. [Recommendations](#11-recommendations)

---

## 1. Architecture Overview

The communication stack is layered as follows:

```
┌─────────────────────────────────────────────┐
│  Application Services                        │
│  (Notifications, Calls, Music, Voice, etc.)  │
├─────────────────────────────────────────────┤
│  Pebble Protocol (25+ endpoints)             │  ← NO encryption
│  PebblePacket serialization                  │  ← NO authentication
├─────────────────────────────────────────────┤
│  PPoG (Pebble Protocol over GATT)            │  ← NO integrity check
│  Windowed reliability, 5-bit sequence        │  ← NO replay protection
├─────────────────────────────────────────────┤
│  GATT Client/Server                          │  ← Custom Pebble UUIDs
│  (Kable library abstraction)                 │
├─────────────────────────────────────────────┤
│  BLE Link Layer                              │  ← ONLY security layer
│  (OS-managed encryption, bonding)            │
└─────────────────────────────────────────────┘
```

**Key files:**
- `libpebble3/src/commonMain/.../connection/bt/ble/pebble/PebbleBle.kt` — Connection orchestrator
- `libpebble3/src/commonMain/.../connection/bt/ble/ppog/PPoG.kt` — PPoG protocol state machine
- `libpebble3/src/commonMain/.../connection/bt/ble/pebble/PebblePairing.kt` — Pairing logic
- `libpebble3/src/commonMain/.../connection/bt/ble/pebble/ConnectivityWatcher.kt` — Connection status
- `libpebble3/src/commonMain/.../protocolhelpers/ProtocolEndpoint.kt` — All protocol endpoints

---

## 2. Encryption & Authentication Analysis

### 2.1 No Application-Layer Encryption

**Finding: CRITICAL**

A comprehensive search of the entire codebase reveals **zero application-layer encryption**. No references to AES, ChaCha20, AEAD, or any cipher were found in the protocol handling code. All data above the BLE link layer is plaintext.

### 2.2 No Mutual Authentication

**Finding: CRITICAL**

After BLE bonding completes, there is **no additional authentication handshake**. The connection flow in `PebbleBle.kt:42-136` is:

1. GATT connect
2. Service discovery
3. Connection parameter negotiation
4. Connectivity status read (flags from watch — **trusted without verification**)
5. BLE pairing/bonding (if needed)
6. PPoG reset handshake
7. Session starts — **no challenge-response, no shared secret, no proof of identity**

### 2.3 No Message Integrity

**Finding: CRITICAL**

- No HMAC, MAC, or digital signatures on any packets
- CRC32 is used only for file transfers (`Crc32Calculator.kt`) — **CRC32 is not cryptographic** and can be trivially forged (polynomial 0x04C11DB7)
- PPoG packets have only a 5-bit sequence number for flow control, no integrity check

### 2.4 BLE Bonding — The Only Security Layer

The app relies on OS-managed BLE bonding:

**Android** (`GattServer.android.kt:238-270`):
- Characteristics use `PERMISSION_READ_ENCRYPTED` and `PERMISSION_WRITE_ENCRYPTED`
- This enforces BLE link-layer encryption at the GATT level

**iOS** (`GattServer.ios.kt`) — **CRITICAL WEAKNESS**:
```kotlin
// META characteristic
permissions = CBAttributePermissionsReadable  // NO ENCRYPTION REQUIRED!

// PPoG Data characteristic
permissions = CBAttributePermissionsWriteable  // NO ENCRYPTION REQUIRED!
```
iOS GATT server characteristics are configured with **plaintext permissions** — any nearby BLE device can read/write without encryption.

### 2.5 iOS Pairing Is a No-Op

**Finding: CRITICAL** (`Pairing.ios.kt:11-31`)

```kotlin
actual fun isBonded(identifier: PebbleBleIdentifier): Boolean {
    return true  // ALWAYS returns true!
}

actual fun createBond(identifier: PebbleBleIdentifier): Boolean {
    return true  // ALWAYS returns true!
}
```

iOS bond state is derived from the watch's self-reported `ConnectivityStatus` flags (`paired && encrypted`). The phone **trusts the watch's claim** about pairing state without independent verification.

### 2.6 Device Identity — MAC/UUID Only

- **Android**: Device identified solely by MAC address (`PebbleBleIdentifier(macAddress: String)`)
- **iOS**: Device identified by CoreBluetooth peripheral UUID (`PebbleBleIdentifier(uuid: Uuid)`)
- **Neither platform** verifies device identity cryptographically
- Watch serial number is transmitted in `WatchVersionResponse` but **never verified against stored values**

---

## 3. Attack Scenario: Passive Eavesdropping

### 3.1 Sniffing BLE Advertisements

An attacker with a BLE sniffer (e.g., Ubertooth, nRF52840 dongle with Wireshark) can passively observe:

- **Watch name/model** — broadcast in advertisement data
- **Serial number** — in manufacturer-specific data (`PebbleLeScanRecord.kt`)
- **Vendor IDs** — `PEBBLE_VENDOR_ID = 0x0154`, `CORE_VENDOR_ID = 0x0EEA` (`Scanning.kt:98-100`)
- **MAC address** — enables tracking across locations

### 3.2 Sniffing Paired Connection Traffic

**If the attacker can break BLE link encryption** (feasible in several scenarios):

1. **Legacy Pairing (Just Works / Numeric Comparison)**: If the Pebble uses Just Works pairing (no display for numeric comparison), the Temporary Key is 0 and can be sniffed during pairing
2. **LE Legacy Pairing**: Uses short-term key exchange vulnerable to brute force
3. **Captured pairing exchange**: If attacker was present during initial pairing, they can derive the Long Term Key

Once link encryption is broken, **everything is readable** because there is no application-layer encryption. See [Section 6](#6-data-exposure-inventory) for the complete data inventory.

### 3.3 What the Attacker Learns (Passive)

With a successful passive capture:
- Full notification content (SMS, email, app notifications — sender, title, body)
- Incoming/outgoing call details (caller name, phone number)
- Complete calendar including attendees, locations, descriptions
- Music listening habits (artist, album, track, play state)
- Health/fitness data
- Voice dictation audio (Speex-encoded frames)
- Dictation transcription results (full text)
- Watch firmware version, serial number

---

## 4. Attack Scenario: Active MITM

### 4.1 MITM During Initial Pairing

An attacker can perform a classic BLE MITM during first-time pairing:

1. Jam or block the real watch's advertisements
2. Advertise a fake device with Pebble GATT services (UUIDs are public in `LEConstants.kt`)
3. Phone connects to attacker's device
4. Attacker relays traffic to/from real watch (or operates independently)
5. Attacker now holds bond keys for both sides

**Feasibility**: MEDIUM-HIGH — BLE MITM tools exist (GATTacker, BtleJuice, custom nRF52 firmware)

### 4.2 MITM on Established Connection

Even after bonding, an active attacker can:

1. **Force re-pairing**: If attacker causes the watch to appear unbonded (e.g., by sending a spoofed ConnectivityStatus with `paired=false`), the phone will re-initiate pairing (`PebbleBle.kt:100-116`)
2. **Exploit the trust model**: The phone checks `connectionStatus.paired` from the watch's GATT characteristic — a value **set by the remote device**

### 4.3 What the Attacker Can Do (Active MITM)

With an active MITM position:

**Read all data flowing to the watch:**
- See Section 6 for full inventory

**Inject commands as the watch:**
- `PhoneControl.Answer` — **Answer incoming phone calls** (`PhoneControl.kt:41`)
- `PhoneControl.Hangup` — **Hang up active calls** (`PhoneControl.kt:42`)
- `MusicControl.PlayPause/NextTrack/VolumeUp/etc.` — **Control music playback** (`Music.kt:16-28`)
- Timeline action invocations — **Reply to notifications** with arbitrary text
- `AppMessage` — Send arbitrary messages to running watchface/app on phone

**Modify data in transit:**
- Alter notification content before it reaches the watch
- Change caller ID information
- Modify calendar events
- Corrupt firmware updates (CRC32 is non-cryptographic, can be forged)

---

## 5. Attack Scenario: Watch Absent / Out of Range

**Finding: HIGH RISK**

If the victim's watch is out of range or powered off, and the attacker knows (or sniffs) the watch's MAC address / peripheral UUID:

### 5.1 Android Attack

1. Attacker creates a BLE peripheral advertising Pebble service UUIDs
2. Sets its MAC address to match the victim's watch (MAC spoofing is possible with custom BLE firmware)
3. Phone may attempt to reconnect to "its" watch
4. Since Android identifies devices by MAC only, the phone connects to the attacker
5. Attacker's device completes BLE pairing
6. Phone begins sending all notification data to attacker

**Mitigation difficulty**: The phone does check `device.isBonded()` via Android's bond database, so the attacker would need to either:
- Be present during initial pairing to capture the bond key, OR
- Force a re-pairing (e.g., by clearing the phone's bond database via another vulnerability)

### 5.2 iOS Attack

The attack is **easier on iOS** because:
- `isBonded()` always returns `true` (`Pairing.ios.kt:12`)
- `createBond()` always returns `true` (`Pairing.ios.kt:16`)
- Bond state is derived from the watch's `ConnectivityStatus` flags — **which the attacker controls**
- `pinAddress = false` in iOS config (`LibPebbleModule.ios.kt:58`) — no address pinning

### 5.3 No Watch = Full Impersonation

Without the real watch present to "compete" with the attacker:
- No timing conflicts from the real watch trying to connect
- Attacker has clean, uncontested access
- All notification, call, calendar, and health data flows to attacker
- Attacker can send commands back to the phone

---

## 6. Data Exposure Inventory

All data transmitted in plaintext (above BLE link encryption) that an attacker with MITM or broken link encryption can access:

### 6.1 Notifications (Timeline endpoint)

**File:** `packets/blobdb/Timeline.kt:269-313`

| Attribute | Max Size | Content |
|-----------|----------|---------|
| Title | 64 bytes | Notification title / sender name |
| Subtitle | 64 bytes | Secondary sender info |
| Body | 512 bytes | **Full notification text** (SMS, email, WhatsApp, etc.) |
| Sender | 64 bytes | Person who sent the message |
| AppName | 40 bytes | Source app (e.g., "WhatsApp", "Gmail") |
| LocationName | 64 bytes | Location (calendar events) |
| CannedResponse | 512 bytes | Suggested quick replies |
| Paragraphs | 1024 bytes | Full event descriptions |

### 6.2 Phone Calls

**File:** `packets/PhoneControl.kt:29-42`

| Event | Data Exposed |
|-------|-------------|
| IncomingCall | Caller's **full phone number** + **contact name** |
| MissedCall | Caller's **full phone number** + **contact name** |
| Ring/Start/End | Call timing (reveals call patterns) |

### 6.3 Calendar Events

**File:** `calendar/CalendarEvent.kt:19-145`

Complete event data synced:
- Event title, description (up to 300 chars), location
- Start/end times, all-day flag, recurrence
- **All attendees with names and email addresses**
- User's RSVP status (Accepted/Declined/Tentative)
- Calendar name (business vs personal)
- Reminders, availability status

### 6.4 Voice / Audio

**File:** `packets/Audio.kt:12-36`, `packets/Voice.kt:1-134`

| Data | Format | Exposure |
|------|--------|----------|
| Audio stream | Speex-encoded frames | **Raw voice recording from watch microphone** |
| Dictation result | Plaintext words with confidence scores | **Full transcription of voice input** |
| Session info | Speex encoder version, sample rate, bit rate | Metadata |

The voice pipeline sends **raw Speex audio frames** from the watch microphone to the phone for speech-to-text. An eavesdropper captures the user's spoken words.

### 6.5 Music

**File:** `packets/Music.kt:31-94`

- Artist, album, track title
- Playback state, position, play rate
- Volume level
- Music player app package name

### 6.6 Health Data

**Endpoint:** `ProtocolEndpoint.HEALTH_SYNC (911u)` — Health step/activity data synced to phone

### 6.7 App Messages

**Endpoint:** `ProtocolEndpoint.APP_MESSAGE (48u)` — Arbitrary key-value data from third-party watchapps, potentially including sensitive data depending on the app

### 6.8 System Information

**File:** `packets/System.kt:233-308`

- Watch serial number (12 chars)
- BT MAC address (6 bytes)
- Firmware version
- Hardware platform/model
- Language, SDK version

---

## 7. Phone Influence / Command Injection

An attacker impersonating the watch can send these commands to the phone:

### 7.1 Call Control

```
PhoneControl.Answer  (0x01)  → Answer an incoming call
PhoneControl.Hangup  (0x02)  → Hang up the current call
PhoneControl.GetState(0x03)  → Query call state
```

**Impact**: Attacker can **answer the victim's phone calls** remotely and potentially listen in (if combined with audio streaming), or hang up important calls.

### 7.2 Music Control

```
MusicControl.PlayPause      (0x01)
MusicControl.Pause           (0x02)
MusicControl.Play            (0x03)
MusicControl.NextTrack       (0x04)
MusicControl.PreviousTrack   (0x05)
MusicControl.VolumeUp        (0x06)
MusicControl.VolumeDown      (0x07)
MusicControl.GetCurrentTrack (0x08)
```

**Impact**: Minor — attacker can control media playback, potentially cause annoyance or information gathering (requesting current track info).

### 7.3 Notification Replies

Via Timeline action invocations, the attacker can:
- Send **text replies** to SMS/messaging notifications on behalf of the victim
- Trigger notification actions (mark as read, dismiss, custom app actions)

**File:** `endpointmanager/timeline/NotificationActionHandler.android.kt:47-71`

### 7.4 App Launch / Control

```
ProtocolEndpoint.APP_LAUNCH (49u)  → Launch apps on the watch
ProtocolEndpoint.APP_RUN_STATE (52u) → Start/stop watch apps
```

### 7.5 Data Exfiltration Requests

The attacker can request:
- `GetBytes` — Read files from the watch (core dumps, app data)
- `WATCH_VERSION` — Get serial number and device info
- `PHONE_VERSION` — **Get phone OS version and capabilities**

---

## 8. Platform-Specific Vulnerabilities

### 8.1 Android

| Issue | Severity | Location |
|-------|----------|----------|
| GATT chars require `PERMISSION_*_ENCRYPTED` | **Positive** | `GattServer.android.kt:245-250` |
| Device identified by MAC only (spoofable) | HIGH | `PebbleDevice.android.kt:5-24` |
| `BluetoothAdapter.getDefaultAdapter()` deprecated | LOW | `GattServer.android.kt:296` |
| GATT offset parameter ignored (data corruption risk) | MEDIUM | `GattServer.android.kt:139-148` |
| Prepared writes not properly handled | MEDIUM | `GattServer.android.kt:136` |
| MAC address logged in plaintext | LOW | `GattServer.android.kt:85,142` |

### 8.2 iOS

| Issue | Severity | Location |
|-------|----------|----------|
| **GATT chars have NO encryption permissions** | **CRITICAL** | `GattServer.ios.kt` |
| `isBonded()` always returns `true` | **CRITICAL** | `Pairing.ios.kt:12` |
| `createBond()` always returns `true` | **CRITICAL** | `Pairing.ios.kt:16` |
| `pinAddress = false` — no address pinning | HIGH | `LibPebbleModule.ios.kt:58` |
| Bond state from watch's self-reported flags | HIGH | `Pairing.ios.kt:23-30` |
| `phoneRequestsPairing = false` — watch initiates | MEDIUM | `LibPebbleModule.ios.kt:59` |

### 8.3 iOS Is Significantly More Vulnerable

The combination of:
1. No GATT encryption requirements
2. `isBonded()` always true
3. No address pinning
4. Trust in watch-reported bond state

...means **any nearby BLE device can connect to an iOS phone's Pebble GATT server and communicate without encryption or authentication**.

---

## 9. Protocol-Level Vulnerabilities

### 9.1 PPoG Protocol Weaknesses

| Vulnerability | Severity | File:Line |
|--------------|----------|-----------|
| 5-bit sequence numbers (wrap at 31) — replay-friendly | MEDIUM | `PPoGPacket.kt` |
| No packet authentication/integrity | HIGH | `PPoG.kt` |
| Duplicate ACK triggers unlimited retransmission | MEDIUM | `PPoG.kt:224-229` |
| Out-of-sequence packets dropped (no reorder buffer) | MEDIUM | `PPoG.kt:244-255` |
| MTU variable not synchronized (race condition) | MEDIUM | `PPoG.kt:38,289-291` |
| No minimum MTU enforcement | MEDIUM | `PebbleBle.kt:73-83` |
| Unbounded outbound queue (memory exhaustion) | MEDIUM | `PPoG.kt:155` |
| Inbound channel capacity=100, no backpressure | LOW | `PPoG.kt:27` |

### 9.2 Packet Handling Weaknesses

| Vulnerability | Severity | File:Line |
|--------------|----------|-----------|
| No endpoint validation on inbound messages | MEDIUM | `PebbleProtocolHandler.kt:28` |
| Registry lookup uses untrusted endpoint value | MEDIUM | `PebblePacket.kt:71-76` |
| GetBytes transactionId is 1 byte (0-255) — collision risk | MEDIUM | `GetBytesService.kt:34` |
| File transfer size not validated (disk exhaustion) | MEDIUM | `GetBytesService.kt:51` |
| CRC32 used for integrity (trivially forgeable) | MEDIUM | `Crc32Calculator.kt` |
| Predictable temp file paths (TOCTOU) | LOW | `GetBytesService.kt:53` |

### 9.3 Connection Weaknesses

| Vulnerability | Severity | File:Line |
|--------------|----------|-----------|
| Hardcoded, predictable timeouts | LOW | `PPoG.kt:297-298` |
| ConnectivityStatus flags trusted from remote device | HIGH | `ConnectivityWatcher.kt:81-99` |
| No session key derivation or rotation | HIGH | Entire connection layer |
| No perfect forward secrecy | HIGH | Entire connection layer |

---

## 10. Additional Attack Vectors

### 10.1 Denial of Service

- **BLE jamming**: Standard BLE jamming in 2.4GHz band disconnects the watch
- **PPoG flood**: Send rapid duplicate ACKs to trigger unlimited retransmissions (`PPoG.kt:224-229`)
- **Large file transfer**: Claim `numBytes = 4GB` in GetBytes to exhaust disk (`GetBytesService.kt:51`)
- **Queue exhaustion**: Flood inbound PPoG channel (capacity 100) to deadlock connection

### 10.2 Firmware/App Injection

- `PutBytes` endpoint allows pushing firmware and apps to the watch
- Only CRC32 integrity check (non-cryptographic, trivially forged)
- An active MITM could push malicious firmware to the watch
- No code signing verification visible in the mobile app codebase

### 10.3 Tracking / Fingerprinting

- Watch serial number broadcast in BLE advertisements
- MAC address visible during scanning
- Vendor ID (`0x0154`) identifies Pebble devices
- Firmware version, hardware platform available after connection
- Device MAC addresses logged in app logs (extractable on rooted/jailbroken devices)

### 10.4 Debug/Development Interfaces

- WebSocket-based development connection exists (`ktor-server-websockets` dependency)
- `verbosePpogLogging` flag logs all packet contents (`PPoG.kt:56-60`)
- `GetBytesService` logs message contents at verbose level (`GetBytesService.kt:105`)
- If debug logging is enabled, app logs contain all BLE traffic

### 10.5 Bluetooth Classic (Legacy)

- Android supports BT Classic fallback (`supportsBtClassic = true`)
- BT Classic has different (generally weaker) security model
- `PebbleBtClassic.kt` — separate transport with its own attack surface

### 10.6 App-Level Data Leaks

- Notification content synced may include OTP codes (2FA), password reset links
- Calendar data may reveal confidential business meetings
- Health data reveals personal medical/fitness information
- Contact names in caller ID reveal the victim's social graph

---

## 11. Recommendations

### Priority 1: Critical (iOS Encryption)

1. **Add encryption permissions to iOS GATT characteristics**
   - Change `CBAttributePermissionsReadable` → `CBAttributePermissionsReadEncryptionRequired`
   - Change `CBAttributePermissionsWriteable` → `CBAttributePermissionsWriteEncryptionRequired`
   - **File:** `GattServer.ios.kt`

2. **Fix iOS pairing stubs**
   - Implement actual bond verification instead of `return true`
   - **File:** `Pairing.ios.kt`

3. **Enable address pinning on iOS**
   - Set `pinAddress = true` in iOS `BlePlatformConfig`
   - **File:** `LibPebbleModule.ios.kt`

### Priority 2: High (Application-Layer Security)

4. **Implement mutual authentication**
   - Add challenge-response after BLE bonding
   - Store and verify device serial number + fingerprint on reconnection
   - Reject devices that don't match stored identity

5. **Add application-layer encryption**
   - Derive session keys from BLE bond + challenge-response
   - Encrypt PPoG payloads with AES-GCM or ChaCha20-Poly1305
   - This protects against BLE link-layer compromise

6. **Add message authentication codes**
   - HMAC-SHA256 on all protocol messages
   - Prevents injection and modification attacks

### Priority 3: Medium (Protocol Hardening)

7. **Add replay protection**
   - Include timestamps or monotonic counters in messages
   - Reject old/replayed messages

8. **Validate remote ConnectivityStatus**
   - Don't trust the watch's self-reported `paired`/`encrypted` flags
   - Verify independently via OS bond database

9. **Rate-limit PPoG ACK processing**
   - Add backoff for duplicate ACK handling
   - Prevent retransmission flooding

10. **Validate file transfer sizes**
    - Cap GetBytes `numBytes` to reasonable maximum
    - Check available disk space before transfers

11. **Replace CRC32 with cryptographic integrity**
    - Use HMAC or digital signatures for firmware/app verification

### Priority 4: Low (Defense in Depth)

12. **Redact sensitive data from logs** — MAC addresses, packet contents
13. **Add connection parameter bounds checking** — Validate MTU, interval, latency ranges
14. **Implement PPoG packet reordering** — Buffer out-of-sequence packets instead of dropping
15. **Add session timeouts** — Force re-authentication after configurable idle period

---

## Appendix: Key File Reference

| File | Security Relevance |
|------|-------------------|
| `connection/bt/ble/pebble/PebbleBle.kt` | Connection flow, no auth after bonding |
| `connection/bt/ble/pebble/PebblePairing.kt` | Pairing trigger, bonding logic |
| `connection/bt/ble/pebble/ConnectivityWatcher.kt` | Trusts remote-reported status |
| `connection/bt/ble/pebble/LEConstants.kt` | Public GATT UUIDs (attackers clone these) |
| `connection/bt/ble/ppog/PPoG.kt` | No integrity, 5-bit sequence, no replay protection |
| `connection/bt/ble/ppog/PPoGPacket.kt` | Plaintext packet format |
| `connection/bt/ble/transport/GattServer.android.kt` | Encrypted permissions (good) |
| `connection/bt/ble/transport/GattServer.ios.kt` | **No encrypted permissions (critical)** |
| `connection/bt/Pairing.ios.kt` | **Always returns bonded=true** |
| `connection/bt/ble/BlePlatformConfig.kt` | Platform security configuration |
| `packets/PhoneControl.kt` | Call control commands (answer/hangup) |
| `packets/Audio.kt` | Raw audio frames (plaintext) |
| `packets/Voice.kt` | Dictation transcription (plaintext) |
| `packets/Music.kt` | Music metadata (plaintext) |
| `packets/blobdb/Timeline.kt` | Notification content (plaintext) |
| `calendar/CalendarEvent.kt` | Full calendar data with attendees |
| `protocolhelpers/PebblePacket.kt` | No validation on deserialization |
| `services/GetBytesService.kt` | File read from watch, 1-byte transaction ID |
| `util/Crc32Calculator.kt` | Non-cryptographic integrity only |
