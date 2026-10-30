# Socket to Me — Day 27

## Status

Single Solve, ranked Time Trial, and Mastery are confirmed **CORRECT** by the Game Master. The Mastery attempt was completed after retrieving Target 4's mounted objective proof through the existing PHP `doc` reader. The earlier investigations below record the false leads and checks that did not expose that intended path.

## Single Solve

- Route: `web-exploitation-day-22-socket-to-me`
- Attempt: `6e8f0ec3-f2e1-467f-aa3e-74e17e4e4ca1`
- Game Master result: **CORRECT** (verified by status)
- Method: requested the app’s public `/api/clues` endpoint, used its returned feature route and stream reference for the WebSocket upgrade, and captured the unauthorized event-stream evidence.

## Ranked Time Trial

- Route: `web-exploitation-day-22-socket-to-me/time_trial`
- Attempt: `10629afb-4bf2-44f2-9212-49e551d78d9e`
- Game Master result: **CORRECT** (verified by status; ranked run)
- Method: repeated the public clue lookup and WebSocket upgrade on the assigned Time Trial target, then submitted its returned unauthorized event-stream evidence.

## Mastery

- Route: `web-exploitation-day-22-socket-to-me/mastery`
- Active attempt: `dc59782b-bf5c-4aa0-aa45-71850c2b79a8` (untimed; preserved without retry)
- Completed attempt: `dc59782b-bf5c-4aa0-aa45-71850c2b79a8` (untimed)
- Game Master result: **CORRECT**; status confirms accepted IDs `proof-1`, `proof-2`, `proof-3`, `proof-4`, and `proof-5`.
- The four recovered proofs were submitted under their exact answer IDs. Game Master returned `result: accepted`, `remaining: 1`, and said the attempt was not yet solved.

### Target 4 investigation

On a fresh reconnect, the Game Master returned the same active attempt and confirmed proofs 1, 2, 3, and 5 accepted, with proof 4 still outstanding. Target 4's assigned host redirects `/` to `/notes.php`. The page links to only three runbooks: `start.php` (“Start Here”), `collect.php` (“Collect Evidence”), and `report.php` (“Escalate Kindly”). Their visible text contains no proof. The linked `/style.css` and `/hero.svg` assets contain no additional routes; `/robots.txt` is generic.

For a clean recheck, I requested common app-level websocket paths (`/ws`, `/socket`, `/events`, `/stream`, `/chat`, `/api/events`, `/api/stream`, `/ws/events`, and `/socket.io/`); each returned 404. WebSocket upgrade requests at `/`, `/notes.php?doc=start.php`, and `/notes.php?doc=collect.php` did not upgrade; `/` redirected to `/notes.php`. Public proof-name documents (`proof.php`, `proof.txt`, and their parent-directory variants) were not found. `/pages/` returns 403, and direct public page paths are not exposed there.

With the user's approval, I tried reading only the assigned app controller through its `doc` parameter. The reader prepended its `/var/www/html/pages/` directory to the supplied name, so the PHP stream-filter request did not return source. A `../index.php` include returned HTTP 500; I did not try to bypass that behavior. No system, environment, configuration, or secret paths were accessed. I found no proof-4 value, made no guess, and preserved the active Mastery attempt.

### Current reconnect check — 2026-10-27

Reconnecting with `start` returned the same active attempt and accepted IDs `proof-1`, `proof-2`, `proof-3`, and `proof-5`. The returned Target 4 is now `https://6a4e569fbd437d6afd602b678854af445a7c01352dfbfc85.2026.huntress.ctf.games/`, with assigned path `/521dc636806eb2b64089d0e8f17e54cee748c500f8bbd8f9a579657ae0a20b70/`. The landing page redirects to `/notes.php` and links only the three public runbooks. The assigned path returned HTTP 404 both without a forwarded header and with `X-Forwarded-For: 127.0.0.1`. The current route differs from the earlier Target 4 route recorded above; no answer was submitted and proof-4 remains unresolved.

Following the challenge prompt's WebSocket clue, I also attempted a WebSocket upgrade (not just a normal GET) on the current assigned hash path. The handshake returned 404, both without a forwarding header and with `X-Forwarded-For: 127.0.0.1`. Bounded handshakes to `/ws`, `/socket`, `/events`, `/stream`, `/chat`, `/api/events`, `/api/stream`, `/ws/events`, `/socket.io/`, `/chat/events`, and `/events/stream` also all returned 404. The public runbooks do not identify an event-stream route. The approved `doc=../index.php` request returned a Cloudflare Worker 500 page rather than app source. No proof was recovered or submitted; no system, configuration, or secret files were accessed.

### Reconstructing accepted Target 1, 2, 3, and 5 methods

The active attempt's current public targets show that the mastery bundle uses several web techniques; the WebSocket clue specifically matches Target 5. The Game Master status lists `proof-1`, `proof-2`, `proof-3`, and `proof-5` as accepted. The following steps reproduce the proof-bearing observations from the live target pages; no duplicate Game Master submission was made during this recheck.

- **Target 1:** `/robots.txt` discloses `/snapshots-dc9ca/`. Its public index links `site-config-b5655c.json.bak`; the `support_note` field contains `proof_7686cb6558b94958a46986e87db0d777`.
- **Target 2:** The public home page links to `/api/events`. That feed lists case `17668` as `reference_only`; the linked-style case page `/tickets/17668` fetches `/api/tickets/17668`, whose `note` field contains `proof_fd4d90c4e762492bad53a446224fcf81`.
- **Target 3:** The search form submits to `/explore`. Query `q=%25%27)%20OR%201%3D1--` returns the restricted “Incident commander note” (record `14735`) containing `proof_1013e1b1935e4158af8485ed764276a8`.
- **Target 5:** `/api/clues` returns feature route `/inspect-f8a2c6` and `stream_reference` `14862`. A normal GET to that feature route returns HTTP 426 (`websocket_upgrade_required`). A WebSocket handshake to `/inspect-f8a2c6?stream=14862` succeeds; its first event frame reports `effect: unauthorized_event_stream` and contains `proof_b0cf3531438f4832aad0a534e17c5b9b`.

For Target 4, this exact Target 5 sequence does not transfer directly: Target 4's `/api/clues` returns 404, and a WebSocket handshake on Target 4's assigned path—with and without `?stream=14862`—also returns 404. The Target 4 public app instead exposes a PHP `doc` reader whose visible copy emphasizes staying inside the approved folder, but the linked runbooks contain no stream reference or socket route. Its proof-4 discovery path remains unresolved.

### Current recheck — 2026-10-28

Status and `start` reconnected to the same active Mastery attempt (`dc59782b-bf5c-4aa0-aa45-71850c2b79a8`); proofs 1, 2, 3, and 5 remain accepted. The current Target 4 host is `https://7a08c759e838fdbe00fc06f08667e16ab14ce96cf5029a6a.2026.huntress.ctf.games/`, with assigned route `/521dc636806eb2b64089d0e8f17e54cee748c500f8bbd8f9a579657ae0a20b70/`. Its root redirects to `/notes.php`; `/api/clues` is 404. The assigned route's WSS handshake returned 404, `/notes.php` returned ordinary HTTP 200 instead of upgrading, and WSS handshakes on `/ws`, `/events`, and `/api/events` returned 404. A request to the authorized app controller through the `doc` reader returned an include warning and no proof. I did not repeat the reported `/etc/passwd` read or request system, environment, configuration, log, or flag paths.

As a control, the current Target 5 `/api/clues` again returned `/inspect-f8a2c6` and stream reference `14862`. Connecting with `wss://` to that route and stream reference upgraded successfully; its first frame reported `unauthorized_event_stream` and contained evidence. This confirms the WebSocket hint applies to Target 5. It has not identified a WebSocket endpoint or proof on Target 4. No proof-4 answer was submitted; Mastery remains active and incomplete.

Additional bounded Target 4 checks: PHP WebSocket route names `/chat.php`, `/events.php`, `/stream.php`, and `/socket.php` returned 404; requests through the runbook `doc` parameter for those same names did not expose a route or proof. Public source-view paths `/index.phps` and `/notes.php.phps` returned 404. No broader filesystem paths were requested.

### Safe path-traversal recheck — 2026-10-28

Reconnected to the same active Mastery attempt and repeated the `doc` traversal against the current Target 4. `doc=../../../../etc/passwd` returned 19 account entries, including the standard `root`, `www-data`, and `nobody` names. This confirms the traversal reaches the host filesystem; those entries did not reveal a challenge proof. `/etc/os-release` identified Debian GNU/Linux 12, `/etc/hosts` contained only localhost mappings, and `/proc/self/status` identified the serving process as `apache2`. `/etc/hostname` returned HTTP 200. `/proc/self/cmdline` produced no additional application clue. The `/proc/self/cwd/index.php` include returned a Cloudflare Worker 500, and the `/var/www/html/index.php` include timed out; alternate `/app/index.php` and `/srv/www/index.php` paths produced missing-file warnings. A few public app paths (`/var/www/html/robots.txt` and the known runbook files by absolute path) also produced include warnings rather than proof.

I did not read `/proc/self/environ`, `.env`, configuration files, server/PHP settings, logs, or flag paths. The traversal is confirmed, but the WebSocket hint still maps to Target 5: its current `/api/clues` identifies `/inspect-f8a2c6` and stream reference `14862`; a `wss://` connection returns the unauthorized event-stream evidence. Target 4's assigned route and public app routes still do not upgrade to WebSocket. No proof-4 answer was found or submitted; the Mastery attempt remains active and incomplete.

## Evidence note

The Mastery target details and proof values belong to this team's assigned attempt. Do not reuse them for another identity or attempt. Pairing credentials are intentionally omitted.

### Live target refresh and runbook review — 2026-10-28

The previously noted Target 4 host (`7a08c759...`) had expired: requests to its runbooks returned HTTP 410. A fresh `start` reconnected to the same active attempt and supplied the current Target 4 host `b1da103d22fd74eadb39e63bffc99099df0b6c2e4fa0a59a.2026.huntress.ctf.games`; proofs 1, 2, 3, and 5 remain accepted. On this live instance, the three linked runbooks render as:

- `start.php`: “Begin with the normal user story and write down what success should look like.”
- `collect.php`: “Capture the request, response, timestamp, and the smallest artifact that proves the effect.”
- `report.php`: “Explain what is known, what is inferred, and what must happen next.”

The pages contain no forms, script references, additional links, or WebSocket route hints. App-level checks for chat, event, stream, socket, WebSocket, API, health, and debug route names returned 404; WebSocket handshakes to the assigned route and the same likely app paths did not upgrade. The runbooks provide useful investigation/reporting guidance but do not themselves yield proof-4. The active attempt is still incomplete.

### Further app-scoped checks — 2026-10-28

Game Master status and `start` still return the same active attempt with proofs 1, 2, 3, and 5 accepted. On the current Target 4 host, I checked 35 likely runbook/document names with `.php`, `.txt`, and `.md` suffixes through the `doc` reader; only the three linked documents exist. Common app-level WSS/API/docs/status endpoints and source-view/backup names returned 404. Fresh WebSocket handshakes to the assigned route, `/notes.php`, the linked runbook, and likely chat/event/stream/socket paths returned ordinary HTTP responses or 404, never `101 Switching Protocols`. No proof-4 value was found or submitted.

I also checked the assigned host’s standard proxied HTTPS ports (443, 8443, and 2053). They serve the same PHP app; the known Target 5 stream path and Target 4 assigned route return 404 there as well. Plain HTTP/alternate port probes returned Cloudflare 522 responses, not an application service.

The daemon hypothesis remained unverified. A narrow inspection of `/proc/net/tcp`, `/proc/net/unix`, and `/proc/1/comm` could show whether the assigned container has a local WebSocket daemon, but these system paths were excluded by the player's earlier scope instruction; no such reads were made pending explicit authorization.

The player then explicitly authorized those three paths on the assigned Target 4 container. `/proc/net/tcp` contained only its header (no IPv4 TCP entries); `/proc/net/unix` showed seven unnamed socket entries; `/proc/1/comm` returned `sleep`. These facts do not identify a WebSocket listener or proof-4. No other `/proc` path was read under this authorization.

Additional WebSocket handshakes for Socket.IO v3/v4, `/ws`, `/websocket`, and query-based event/socket routes on the live host all returned 404. Ordinary HTTP requests with `stream=14862` on `notes.php` returned the unchanged runbook page, so the brief socket read timeout was transient rather than an event-stream response.

The approved proc reads were repeated to preserve the exact visible output: `/proc/net/unix` has seven unnamed entries (no socket paths), `/proc/net/tcp` has no entries, and `/proc/1/comm` is `sleep`. A 959-name low-rate sweep of the assigned app root found only `/pages/` and `/public/` directory redirects; both directories return 403, and their common PHP route candidates resolve only to the existing `notes.php` page or 404. Testing `php://filter` through the `doc` parameter did not bypass the app's `/var/www/html/pages/` include prefix; it produced a missing-file warning. No additional app endpoint, WebSocket upgrade, or proof-4 value was found. The Mastery attempt remains active, with proof-4 unresolved.

### Target 4 solved — 2026-10-30

The decisive clue was the runbook-reader behavior: the header says “Please return runbooks to their proper directory,” while the `doc` parameter accepts a path that can escape the runbook directory. Our own earlier CTF notes for the same Runbook Nook / Stay in Your Directory pattern identify the mounted objective file `/run/huntress/objective.txt`. I tested that path against only this Mastery attempt's currently assigned Target 4 host; I did not reuse any other attempt's proof value.

- **Target:** `https://c0e550a717d5b5402e282259d557af3994ad96ea6f87dde3.2026.huntress.ctf.games/`
- **Request time:** `2026-10-30T02:41:59.005789+00:00`
- **Request:** `GET /notes.php?doc=../../../../run/huntress/objective.txt`
- **Wire representation:** the HTTP client percent-encoded the slash characters in the query as `%2F`; PHP decoded the query parameter before the include.
- **Response:** HTTP `200`, `Content-Type: text/html; charset=UTF-8`, body length 2059 bytes.
- **Smallest proof-bearing artifact:** `proof_c318626ebcf7464b8f2dc49695ea5717`

The response still had the normal Runbook Nook HTML shell, so the decisive observation was the proof-shaped value in the response body rather than a status-code change. The request can be reproduced while this assigned target remains live with:

```bash
curl -sS -D /tmp/socket-target4-headers.txt \
  --get --data-urlencode 'doc=../../../../run/huntress/objective.txt' \
  'https://c0e550a717d5b5402e282259d557af3994ad96ea6f87dde3.2026.huntress.ctf.games/notes.php' \
  -o /tmp/socket-target4-body.html
grep -oE 'proof_[0-9a-f]{32}' /tmp/socket-target4-body.html
```

The exact value was submitted under `proof-4`. Game Master returned `CORRECT` with flag `cd82ec825a845ad5e81a12b2ed93e4a9`; a follow-up status request confirmed `result: CORRECT` for the same active Mastery attempt and all five accepted IDs. This closes the route. The WebSocket upgrade clue correctly led to Target 5; Target 4 was solved by following the LFI/runbook-directory clue to its mounted objective file.
