# Team Project Tracker — real-time edition

Everyone who opens the site sees every change instantly (add, edit, delete, progress, problems, uploads) — no refresh needed.

## Everyone can save at the same time
Nobody has to wait for anyone and nobody's save replaces someone else's. The server merges
overlapping saves instead of picking a winner:

- Two people edit **different parts of the same task** at once (one writes notes, one changes
  progress) → both changes are kept.
- Several people **report problems or add links/files** to the same task at once → all are kept.
- Several people **create tasks** at once → all are created.
- Someone has the Edit window open while a teammate changes the task → saving only applies what
  *they* changed; it does not undo the teammate's change.
- Only if two people change the **exact same field** (e.g. both set progress) at the **exact same
  moment** does one value win — whichever reaches the server last — and every screen then shows that value.
- If someone deletes a task while another person is editing it, the deletion stands.

## Run it on your computer
Requires [Node.js 22.13+](https://nodejs.org) (uses the built-in SQLite). No `npm install` needed.

    node server.js
    # open http://localhost:3000

Teammates on the same Wi-Fi can open `http://<your-computer-IP>:3000`.

## Put it online
You need a host that runs a **Node.js server** and gives it a **persistent disk** (the database
file, including uploaded files, is saved there). Render, Railway and Fly.io all work, as does any VPS.
Static-only hosts (GitHub Pages, Netlify, Vercel) will NOT work — they can't keep the
live connection open or store data.

Settings for any host:

| Setting        | Value                                                        |
|----------------|--------------------------------------------------------------|
| Start command  | `node server.js`                                             |
| Environment    | `DATA_DIR` = the path where you mounted the persistent disk (e.g. `/data`) |
| Persistent disk| Mount at the same path as `DATA_DIR`                         |
| Health check   | `/healthz`                                                   |

If the host supports Docker, the included `Dockerfile` already stores data in `/data` — mount your disk there.

**Without a persistent disk, your tasks are erased every time the server restarts or redeploys.**

## Protect the site with a password (recommended)
Set two environment variables and the browser will ask for them before showing anything:

    SITE_USER=team
    SITE_PASSWORD=choose-a-long-password

Without these, anyone who knows the web address can read and change the tasks (the in-app
brand logins only hide things on screen; they don't protect the data on the server).

## Database
Everything (tasks, attachments, board order) lives in one SQLite file: `DATA_DIR/tracker.db`.

- **Revision:** a counter stored in the database goes up in the same transaction as every
  change. Browsers are told the new revision over the live connection (and re-sync if they
  reconnect with an older one), so every open screen refreshes by itself. The server also checks
  the counter every ~1.5 s, so changes made by anything else using the same file are announced too.
- **Migrations:** `migrations/*.sql` are applied once, in filename order, on startup. To change
  the schema, add `002_something.sql`; never edit one that has already shipped.
- **Upgrading from the tasks.json version:** on first start the old `tasks.json` and `files/`
  folder in `DATA_DIR` are imported automatically (once; the originals are left in place and can
  be deleted after you've checked everything is there).
- **Single server only:** run one instance against the disk (SQLite isn't meant for several
  machines sharing a network drive).

## Backups
An hourly snapshot of the whole database is written to `DATA_DIR/backups/tracker-<time>.db`
(newest 100 kept). To restore, stop the server, then copy a snapshot over `tracker.db` and
delete `tracker.db-wal` and `tracker.db-shm` if they exist.
