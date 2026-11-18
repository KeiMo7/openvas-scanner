# Multiple credentials per service

A scan target can carry several credentials for the same service (SSH, SMB,
SNMP, KRB5, ESXi). Each credential may be restricted to a list of hosts.
When a host is scanned, the credential matching that host is selected and
published as the scan preferences read by the NASL scripts.

## Credential format

Credentials are part of the target in the scan JSON. The optional `hosts`
field ties a credential to specific hosts.

```json
"credentials": [
  { "service": "ssh", "port": 22,
    "up": { "username": "default", "password": "pass" } },
  { "service": "ssh", "port": 2222,
    "hosts": ["192.168.1.0/24", "web.example.com"],
    "usk": { "username": "admin", "password": "passphrase",
             "private": "<base64 key>" } },
  { "service": "smb", "hosts": ["10.0.0.1-10"],
    "up": { "username": "user", "password": "pass" } }
]
```

`hosts` accepts everything `gvm_hosts_new()` understands: single IPs,
hostnames, CIDR networks and ranges.

## Flow

1. **openvasd (Rust, `pref_handler.rs`)**, in `prepare_credentials_for_openvas()`:
   - The **first credential without `hosts`** (missing or empty) of each
     service is written as the regular default preferences (the same
     preferences used before this feature). Credentials with `hosts` and
     later credentials without `hosts` are not written as defaults.
   - The complete credential list is serialized into one scan preference,
     `multi-credentials`, as a JSON string.
2. **openvas (C, `src/openvas.c`)**, in
   `overwrite_openvas_prefs_with_prefs_from_client()`:
   - If `multi-credentials` is set, `process_credentials_json()`
     (`misc/credentials.c`) parses it into `globals->credentials`, a list of
     `credential_t` (type, service data, `gvm_hosts_t` host list).
   - SSH private keys are base64 stored with `store_file()` under a generated
     UUID. The UUID is later used as the key preference value.
   - The `multi-credentials` preference is then blanked so the secrets are not
     reachable by NASL. The scanprefs are removed from Redis right after.
3. **Per-host process (`src/attack.c`)**, in `attack_host()`, before any plugin
   runs: `override_host_credentials(globals, args->host)`.
   - For each service, the list is walked in order and the **first**
     credential whose `hosts` list contains the scanned host is chosen.
   - It is stored with `prefs_set()`, replacing the default values. This only
     affects the forked per-host process, so other hosts are unaffected.
   - If nothing matches, the default credential stays in place.

## Rules

- Matching is first-match-wins, in the order given in the JSON.
- A credential without `hosts` never matches in C; it can only be the default
  (the first one without hosts, per service).
- Each service is selected independently; an SSH match doesn't influence SMB.
- A matching credential replaces **all** values of that service. Missing
  optional values are set to an empty string, so nothing leaks from the
  default credential. For SSH, a missing port is set to `0`, which lets the
  NASL scripts choose their default port.
- Entries in `hosts` that are empty or not strings are ignored. If no valid
  entry is left, the credential has no host list and acts as a default
  candidate.
- Credentials of unknown services, or lacking the required auth object
  (`up`, `usk`, `snmp`, `krb5`), are skipped with a warning.

## Preferences set per service

| Service | Preferences |
|---------|-------------|
| SSH     | `auth_port_ssh`, login, password, key passphrase, privilege login/password, private key (UUID) |
| SMB     | login, password |
| SNMP    | community, username, password, auth algorithm, privacy password, privacy algorithm |
| KRB5    | login, password, realm, kdc |
| ESXi    | login, password |

## Code map

- `rust/src/models/credential.rs`: the `hosts` field.
- `rust/src/openvas/pref_handler.rs`: default selection and `multi-credentials`.
- `misc/credentials.c/.h`: parsing, host matching, `override_host_credentials()`.
- `misc/scanneraux.c/.h`: `credentials` in `scan_globals`, `store_file()`.
- `src/openvas.c`, `src/attack.c`: parse on load, override per host.
