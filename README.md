# MyKevo — Home Assistant Integration

A Home Assistant custom integration for **Kwikset Kevo** smart locks, providing real-time lock control and battery monitoring via the Unikey cloud platform.

---

## Features

- **Lock / Unlock** your Kevo locks directly from Home Assistant
- **Real-time state updates** via WebSocket — no polling delay
- **Battery level sensor** for each lock (reported as a percentage)
- **Jammed state detection** — surfaces lock jam conditions in HA
- **Multi-lock support** — choose which locks to add during setup
- **Re-authentication flow** — HA prompts for new credentials if the session expires

---

## Prerequisites

- A [mykevo.com](https://mykevo.com) account
- You must have **opted into the new Kevo experience** on mykevo.com
- The account used must hold an **Admin eKey** for each lock you want to control
- Home Assistant with [HACS](https://hacs.xyz) installed

---

## Installation

### Via HACS (Recommended)

1. Open HACS in your Home Assistant sidebar
2. Click the **⋮** menu (top right) and select **Custom repositories**
3. Add the repository URL and set the category to **Integration**:
   ```
   https://github.com/ahnt99/Kevoplus-Intregration
   ```
4. Find **MyKevo** in the HACS integration list and click **Download**
5. Restart Home Assistant

### Manual Installation

1. Download [zip](https://github.com/ahnt99/Kevoplus-Intregration/archive/refs/heads/main.zip) from this repository
2. Extract and copy files in the `mykevo` folder into your HA `config/custom_components/mykevo` directory:
   ```
   config/
   └── custom_components/
       └── mykevo/
           ├── __init__.py
           ├── api.py
           ├── config_flow.py
           ├── const.py
           ├── lock.py
           ├── manifest.json
           ├── sensor.py
           └── strings.json
              └── translations/
                  └── en.json
              └── brand/
                  ├── icon.png
                  ├── icon@2x.png
                  ├── logo.png
                  └── logo@2x.png 
   ```
3. Restart Home Assistant

---

## Configuration

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **MyKevo**
3. Enter your mykevo.com **username** and **password**
4. Select the locks you want to add to Home Assistant
5. Click **Submit**

Your locks will appear as devices with a **Lock** entity and a **Battery Level** sensor each.

---

## Entities

Each lock creates two entities:

| Entity | Type | Description |
|--------|------|-------------|
| `lock.<lock_name>_lock` | Lock | Control and monitor lock state |
| `sensor.<lock_name>_battery_level` | Sensor | Battery level (%) |

### Lock States

The lock entity reports the following states:

| State | Description |
|-------|-------------|
| Locked | The bolt is fully extended |
| Unlocked | The bolt is retracted |
| Jammed | The bolt is obstructed and cannot complete its movement |
| Locking | A lock command is in progress |
| Unlocking | An unlock command is in progress |

---

## Options

After setup you can change which locks are active without re-entering your credentials:

1. Go to **Settings → Devices & Services**
2. Find **MyKevo** and click **Configure**
3. Update your lock selection and click **Submit**

---

## How It Works

The integration authenticates with the Unikey identity platform using an OAuth2 PKCE flow, mirroring what the mykevo.com web app does. After login, a persistent **WebSocket connection** is maintained to receive instant push notifications whenever a lock's state changes — so the lock entity in HA updates immediately when you use a physical key, the keypad, or the Kevo app.

The access token is automatically refreshed in the background before it expires, so the integration stays connected without requiring you to re-enter credentials.

---

## Troubleshooting

**"Invalid authentication" during setup**
- Confirm your username and password work at [mykevo.com](https://mykevo.com)
- Make sure you have opted into the **new Kevo experience**
- Ensure the account has an **Admin eKey** for the locks you want to add

**Lock shows as unavailable**
- Check that your Home Assistant instance has internet access
- Try reloading the integration via **Settings → Devices & Services → MyKevo → ⋮ → Reload**

**Re-authentication prompt appears**
- Your session has expired. Enter your mykevo.com credentials again when prompted.

---

## Requirements

The following Python packages are installed automatically by HA:

- `httpx >= 0.27.0`
- `websockets >= 12.0`
- `pkce >= 1.0.3`
- `PyJWT >= 2.8.0`

---

## Credits

Based on the original work by [@dcmeglio](https://github.com/dcmeglio):
- [pykevoplus](https://github.com/dcmeglio/pykevoplus)
- [home-assistant-kevo](https://github.com/dcmeglio/home-assistant-kevo)
