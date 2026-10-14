# User Guide — Time-Locked Message Capsule

## What this is

A web page where you can seal a text message or a small file into a
"capsule" that literally cannot be opened — by you, by anyone hosting
this server, by anyone — until a time you choose has passed.

## Creating a capsule

1. Open the app in a browser (`http://localhost:3000` if running
   locally).
2. Optionally give it a **label** — this is stored unencrypted, so
   don't put anything sensitive in it (it's just there to help you
   recognize your own capsules in the list).
3. Choose **Text message** or **File**, and fill in the content.
4. Choose when it unlocks: a number of hours/days/years from now, or
   an exact date and time.
5. Read the warning. Click **Seal capsule**.

You'll get back a **capsule ID** and a **shareable link**. Save the
link — it's the only way to check on or open the capsule later. There
is no login and no recovery: if you lose the link and the ID, the
capsule is still safe (nobody else can open it early either), but you
personally won't be able to find it again once the server's in-memory
list of capsules is gone (see the storage caveat in `DESIGN.md`).

## Checking / opening a capsule

* Open the shareable link, or paste the capsule ID into the "Check a
  capsule" box.
* While locked, you'll see a live countdown to the unlock time.
* Once the target time passes, the page shows **pending-decryption**
  for a few seconds (the server is fetching and verifying that
  moment's beacon value) and then automatically flips to
  **unlocked**, revealing the message or a download link for the
  file. You don't need to refresh — the page polls automatically.

## What "irreversible" actually means here

Once you click **Seal capsule**:

* There is no edit, cancel, or "unlock early" button, for you or for
  an administrator of this server.
* The plaintext is not stored anywhere after encryption — only the
  ciphertext is kept, until the beacon reaches the target round and
  the automatic decryption service opens it.
* The unlock time you get back may be a few seconds later than what
  you typed — capsules unlock on beacon *round* boundaries (about
  every 3 seconds on the network this app uses), so your requested
  time gets rounded up to the next round.

## Example use cases

* **Personal time capsule** — write a message to your future self,
  unlock in a year.
* **Scheduled disclosure** — seal an announcement or a decision ahead
  of time so its timing can't be disputed after the fact; anyone can
  verify it was written before it unlocked because the ciphertext
  (and its target round) can be shared before the unlock time.
* **Sealed-bid auction commitment** — participants seal their bids to
  the same unlock round; all bids become simultaneously readable, so
  no one can see others' bids before committing their own.

## Security considerations & limitations

* **This is a course project, not audited software.** Don't use it
  for anything where a real security guarantee matters.
* **The label is not encrypted.** Only the message/file content is.
* **Capsules live in server memory only.** Restarting the server
  loses every capsule that hasn't been created since. This is a
  deliberate scope decision for the assignment (see `DESIGN.md`), not
  a property you should rely on for anything you actually care about.
* **Anyone with the capsule ID can check its status and, once
  unlocked, read it.** Treat the shareable link like the message
  itself — sealing doesn't hide *who* is allowed to eventually read
  it, only *when*.
* **The server needs outbound internet access** to reach the drand
  beacon; if it can't, capsules will sit at **pending-decryption**
  indefinitely past their unlock time until connectivity is restored
  (nothing is lost — see the retry behavior in `DESIGN.md`).


## Notifications and recipients

When creating a capsule you can list recipients and give a **webhook
URL**. When the capsule unlocks, the server sends a JSON event
(`capsule.unlocked`, with a link to the capsule) to that URL. Point it
at a Slack/Discord/Teams incoming webhook, or at Zapier/Make/IFTTT to
turn it into an email or SMS. The notification never contains the
message itself. Recipients are labels only: **anyone with the link can
read the capsule once it unlocks.**

## Sealed-bid auction

1. *Sealed-bid auction* tab -> create an auction with a reveal delay.
   Share the auction ID/link.
2. Bidders enter name + bid and click **Seal my bid**. They get a
   *commitment* (a SHA-256 receipt of their encrypted bid) - keep it.
3. Until the reveal time everybody sees only the number of bids and the
   commitments. At the reveal time all bids open at once; if all bids
   are numbers the highest is shown.
4. Bids are refused after the reveal round arrives.

## Dead man's switch

1. *Dead man's switch* tab -> write a message and choose how often you
   will check in (e.g. every 7 days). Save the **check-in token**
   (shown once; also stored in your browser).
2. Click **Check in** before each deadline; this pushes the deadline
   forward.
3. If you miss a deadline the message is released automatically.
   After the deadline passes you can no longer check in.
4. Note: the server holds your message in memory while the switch is
   armed (see DESIGN.md section 5.3).

## API quick reference

| Method & path | Purpose |
|---|---|
| `POST /api/capsules` | create a capsule (`message` or `file_base64`+`file_name`; `unlock_in_seconds` or `unlock_at`; optional `label`, `recipients`, `webhook_url`) |
| `GET /api/capsules/:id` | status / content once unlocked |
| `POST /api/auctions` | `{label, reveal_in_seconds}` |
| `POST /api/auctions/:id/bids` | `{bidder, bid}` -> commitment |
| `GET /api/auctions/:id` | status, commitments, revealed bids |
| `POST /api/switches` | `{message, checkin_interval_seconds, label?, webhook_url?}` -> id + token |
| `POST /api/switches/:id/checkin` | `{token}` |
| `GET /api/switches/:id` | status; content only after it fires |
| `GET /healthz` | liveness probe |
