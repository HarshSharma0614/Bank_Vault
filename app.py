from flask import Flask, request, render_template, redirect, url_for, session, Response
import sqlite3
import os
import secrets
import datetime
import time
import base64
import random

from waf import waf_filter, login_waf_filter

app = Flask(__name__)

LOGIN_TIMEOUT_SECONDS = 300
MAX_STARS = 5

LOGIN_BYPASS_MODE = random.randint(1, 4)
HEARTBEAT_MAX_GAP = 30

LOGIN_RATE_WINDOW_SECONDS = 30
LOGIN_RATE_MAX_ATTEMPTS = 5
LOGIN_RATE_LOCKOUT_SECONDS = 30
_login_attempt_log = {}
_login_locked_until = {}

CCTV_RATE_WINDOW_SECONDS = 60
CCTV_RATE_MAX_ATTEMPTS = 5
CCTV_RATE_LOCKOUT_SECONDS = 300
_cctv_attempt_log = {}
_cctv_locked_until = {}


def _rate_limit_key():
    return session.get("pid") or request.remote_addr or "unknown"


def _rate_limit_guard(attempt_log, locked_until_map, window, max_attempts, lockout_seconds):
    key = _rate_limit_key()
    now = time.time()

    locked_until = locked_until_map.get(key, 0)
    if now < locked_until:
        return int(locked_until - now) + 1

    log = attempt_log.setdefault(key, [])
    log[:] = [t for t in log if now - t < window]
    log.append(now)

    if len(log) > max_attempts:
        locked_until_map[key] = now + lockout_seconds
        log.clear()
        return lockout_seconds

    return 0


def login_brute_force_guard():
    wait = _rate_limit_guard(
        _login_attempt_log, _login_locked_until,
        LOGIN_RATE_WINDOW_SECONDS, LOGIN_RATE_MAX_ATTEMPTS, LOGIN_RATE_LOCKOUT_SECONDS,
    )
    if wait:
        return render_template(
            "login.html",
            error=f"\U0001F6A8 Cyber-Sentinel: too many attempts. Locked for {wait}s.",
            reason=None,
            theme=vault_theme(),
        ), 429
    return None


def cctv_brute_force_guard():
    wait = _rate_limit_guard(
        _cctv_attempt_log, _cctv_locked_until,
        CCTV_RATE_WINDOW_SECONDS, CCTV_RATE_MAX_ATTEMPTS, CCTV_RATE_LOCKOUT_SECONDS,
    )
    if wait:
        mins, secs = divmod(wait, 60)
        wait_str = f"{mins}m {secs}s" if mins else f"{secs}s"
        return render_template(
            "cctv_records.html",
            error=f"\U0001F6A8 Too many lookups. Locked for {wait_str}.",
            theme=vault_theme(),
        ), 429
    return None

HERE = os.path.dirname(__file__)
DB_PATH = os.path.join(HERE, "ctf.db")
PLAYERS_DB_PATH = os.path.join(HERE, "players.db")

_SECRET_PATH = os.path.join(HERE, ".secret_key")
if os.path.exists(_SECRET_PATH):
    with open(_SECRET_PATH, "r") as f:
        app.secret_key = f.read().strip()
else:
    key = secrets.token_hex(32)
    with open(_SECRET_PATH, "w") as f:
        f.write(key)
    app.secret_key = key

app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(seconds=LOGIN_TIMEOUT_SECONDS)

with open(os.path.join(HERE, ".flag")) as f:
    FLAG = f.read().strip()

with open(os.path.join(HERE, ".hurdle2")) as f:
    _lines = f.read().splitlines()
    H2_SHIFT = int(_lines[0])
    H2_PHRASE = _lines[1].strip()
    H2_CIPHER = _lines[2].strip()

with open(os.path.join(HERE, ".exname")) as f:
    CCTV_PASSWORD = f.read().strip()

with open(os.path.join(HERE, ".fingerprint")) as f:
    FINGERPRINT_PASSWORD = f.read().strip()

WORDLIST_PATH = os.path.join(HERE, "wordlist_export.txt")

STORY = {
    "title": "Ganton Bank",
    "target": "the vault access codes",
    "opening": "Sweet's got a lead: Ganton Bank is moving vault codes onto a new system before a shipment goes out Friday.",
    "lore": "Word is the site manager's own family has history here — his "
    "great-grandfather was one of the delegates at the old Treaty of "
    "Neuberg, and the story goes he walked away from that table with a "
    "\"goated puzzle\" nobody could ever crack. Whatever that puzzle "
    "actually was, it's apparently why the manager insists on a "
    "tic-tac-toe kiosk guarding the inner vault door to this day. Don't "
    "go digging through this page's source for that one, CJ — it isn't "
    "written down anywhere. You'll have to actually beat the thing.",
}

PORTAL_FLAVOR = [
    "CJ: Man, I'm just standing here at reception looking stupid, hurry the fuck up.",
    "Sweet: Security guard just walked past the desk, CJ. Don't make it weird.",
    "Big Smoke: Man's asking me about a savings account, I don't know shit about savings accounts.",
    "CJ: This receptionist keeps staring at me, move it.",
    "Sweet: You in yet? Talk to me, CJ's sweating out here.",
    "Big Smoke: This fool wants a loan application now, what do I even say?",
    "CJ: If that camera pans this way one more time I'm walking the fuck out.",
    "Sweet: Grove Street's waiting on this, hurry your ass up.",
    "CJ: My hands are sweating on this damn pen, they think I'm filling out a form.",
    "Sweet: Don't get cocky. Just get the codes and get out.",
    "CJ: There's a line forming behind me at this desk, c'mon.",
    "Big Smoke: Tenpenny's car just pulled into the lot. Whatever you're doing, do it faster.",
    "CJ: Every second I'm standing here is a second too many, man.",
    "Sweet: Focus up. Grove Street's counting on this shit.",
]

GAME_FLAVOR = [
    "Sweet: Don't actually win, fool — play it dumb.",
    "CJ: This damn computer thinks it's smarter than me.",
    "Big Smoke: I never liked games where the house always wins, man.",
    "CJ: Hurry it up, my legs are getting tired standing at this desk.",
    "Ryder: Ha! Bet your ass can't even lose to a computer on purpose.",
    "Sweet: Let it win, that's the whole damn plan, CJ.",
    "CJ: C'mon, c'mon, one more move — we ain't got all day.",
    "Big Smoke: Whatever you do, don't actually win. Trust me on this one.",
    "CJ: Some asshole in a suit just walked past, keep it moving.",
    "Sweet: This receptionist's on the phone with somebody. Could be nothing. Could be everything.",
    "CJ: This kiosk game's rigged as hell — good thing that's the whole point.",
    "Big Smoke: You hear that? Sounded like Tenpenny's voice. Move it, CJ.",
]

def cj_key_lines(xor_key):
    return [
        {"t": 30, "text": f"CJ: Man, hurry up — somebody at the desk said the key's {xor_key}."},
        {"t": 60, "text": f"CJ: You even listening to me? I said the damn key is {xor_key}."},
        {"t": 90, "text": f"CJ: This better be it, {xor_key} — I ain't standing here all fucking day."},
    ]


def random_flavor(pool):
    return random.choice(pool)


@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html"), 500


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_players_db():
    conn = sqlite3.connect(PLAYERS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def xor_encrypt(plaintext: str, key: str) -> str:
    data = plaintext.encode()
    k = key.encode()
    out = bytes(b ^ k[i % len(k)] for i, b in enumerate(data))
    return base64.b64encode(out).decode()


def current_player():
    pid = session.get("pid")
    if not pid:
        return None
    conn = get_players_db()
    row = conn.execute("SELECT * FROM players WHERE player_id=?", (pid,)).fetchone()
    conn.close()
    return row


def bump_query_count():
    """Bumped on every /login and /portal/search attempt, success or
    failure -- an attempt is an attempt. The very first call for a given
    player is also the moment the solve-time clock starts (see
    heartbeat() below, which refuses to credit any elapsed time until
    query_count > 0)."""
    pid = session.get("pid")
    if not pid:
        return
    now = time.time()
    conn = get_players_db()
    row = conn.execute("SELECT query_count FROM players WHERE player_id=?", (pid,)).fetchone()
    if row and row["query_count"] == 0:
        conn.execute(
            "UPDATE players SET query_count = query_count + 1, last_heartbeat_at=? "
            "WHERE player_id=? AND flag_reached=0",
            (now, pid),
        )
    else:
        conn.execute(
            "UPDATE players SET query_count = query_count + 1 WHERE player_id=? AND flag_reached=0",
            (pid,),
        )
    conn.commit()
    conn.close()


def sync_max_stars(stars):
    pid = session.get("pid")
    if not pid:
        return
    conn = get_players_db()
    conn.execute(
        "UPDATE players SET max_stars = MAX(max_stars, ?) WHERE player_id=? AND flag_reached=0",
        (stars, pid),
    )
    conn.commit()
    conn.close()


def bump_wanted():
    """Call on any malformed/failed SQL attempt. Returns True if this just
    tripped the 5-star mission-failed threshold."""
    stars = session.get("wanted_stars", 0) + 1
    session["wanted_stars"] = min(stars, MAX_STARS)
    sync_max_stars(session["wanted_stars"])
    return session["wanted_stars"] >= MAX_STARS


def require_player():
    if not session.get("pid"):
        return redirect(url_for("root"))
    return None


_current_token = None
_current_token_created = 0
_valid_tokens = {}
_MAX_TRACKED_TOKENS = 500
_vault_table = "vault_secrets"
_current_xor_key_value = None


def discover_vault_table(conn):
    """Find whatever the vault table is currently named, regardless of
    what _vault_table's in-memory default says. Needed because a server
    restart resets the Python-side variable to 'vault_secrets', but the
    actual table in ctf.db may already have been renamed by a previous
    run."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND "
        "(name='vault_secrets' OR name LIKE 'vt\\_%' ESCAPE '\\')"
    ).fetchone()
    return row[0] if row else "vault_secrets"


def _mint_new_token():
    """Generate a brand new session key/xor key pair and write it into the
    vault table. This is the only place a new token is ever created --
    called either lazily once (server just started, nothing to serve
    yet) or explicitly by force_rotate_token() when a token has just been
    burned. The new token is ADDED to the set of valid tokens -- older
    ones already handed out are left alone and stay valid for whoever is
    still legitimately using them."""
    global _current_token, _current_token_created, _current_xor_key_value
    new_token = secrets.token_hex(8)
    new_key = secrets.token_urlsafe(9)
    enc = xor_encrypt(new_token, new_key)

    conn = get_db()
    actual_table = discover_vault_table(conn)
    conn.execute(f"DELETE FROM {actual_table} WHERE label='xor_key'")
    conn.execute(f"UPDATE {actual_table} SET data=? WHERE label='session_token_enc'", (enc,))
    conn.commit()
    conn.close()

    _current_token = new_token
    _current_token_created = time.time()
    _current_xor_key_value = new_key
    _valid_tokens[new_token] = _current_token_created

    while len(_valid_tokens) > _MAX_TRACKED_TOKENS:
        oldest = next(iter(_valid_tokens))
        del _valid_tokens[oldest]


def ensure_token_fresh():
    """Make sure a session key exists. This does NOT rotate on any kind
    of background timer -- a key that's live stays live, unchanged, for
    as long as nobody burns it and its game timer hasn't run out. The
    only case handled here is the very first request the server has ever
    served, where nothing has been minted yet."""
    if _current_token is None:
        _mint_new_token()


def force_rotate_token():
    """Mint a brand new session key so future SQLi dumps hand back a
    fresh one immediately after a burn -- a failed player is never stuck
    re-discovering the same dead token. This does NOT touch the validity
    of any token minted before it: those remain valid (see _valid_tokens)
    for whichever other player(s) are still legitimately holding them.
    The only thing that invalidates an EARLIER token for a SPECIFIC
    player is that player burning it themselves (session["burned_tokens"],
    checked in token_is_valid's caller) or their own game timer running
    out."""
    _mint_new_token()


def rename_vault_table_on_login_timeout():
    """Rename the vault table -- ONLY called at the exact moment a
    player's /login session is detected to have timed out. This is fully
    decoupled from session-key rotation and fires only on that one
    event, never on a background timer."""
    global _vault_table
    conn = get_db()
    actual_table = discover_vault_table(conn)
    new_table = "vt_" + secrets.token_hex(4)
    conn.execute(f"ALTER TABLE {actual_table} RENAME TO {new_table}")
    conn.commit()
    conn.close()
    _vault_table = new_table


def token_is_valid(token):
    """A token is valid if it was ever minted and hasn't (for THIS
    player) been personally burned -- see the burned_tokens check at the
    call site. It does NOT stop being valid just because a newer token
    has since been minted for someone else."""
    ensure_token_fresh()
    return token in _valid_tokens


def current_xor_key():
    ensure_token_fresh()
    return _current_xor_key_value


def login_seconds_remaining():
    if "login_time" not in session:
        return 0
    return max(0, int(LOGIN_TIMEOUT_SECONDS - (time.time() - session["login_time"])))


def login_session_active():
    if "user" not in session or "login_time" not in session:
        return False
    return login_seconds_remaining() > 0


def game_seconds_remaining():
    if "game_started_at" not in session:
        return 0
    total = session.get("game_timeout_seconds", 900)
    return max(0, int(total - (time.time() - session["game_started_at"])))


def game_session_active():
    if "game_token" not in session or "game_started_at" not in session:
        return False
    return game_seconds_remaining() > 0


def reset_game_state(burn_token=None):
    if burn_token:
        burned = session.get("burned_tokens", [])
        burned.append(burn_token)
        session["burned_tokens"] = burned[-20:]
        force_rotate_token()
    for k in ("game_token", "game_started_at", "game_timeout_seconds", "ttt_board", "ttt_moves", "ttt_unlocked"):
        session.pop(k, None)


def vault_theme():
    return STORY


def handle_login_expiry():
    """Called the moment we detect a player's /login session has just
    timed out. This ONLY logs them out of the employee terminal --
    'user', 'role', and 'login_time' are removed. It deliberately does
    NOT touch (and therefore does not invalidate) their private vault/
    game session: game_token, ttt progress, hurdle2/CCTV progress,
    wanted stars, and burned-token history all survive untouched, so a
    key that was live before the login timer ran out is still live
    after it.

    The vault table name DOES change here -- and only here, exactly
    once per timeout -- per the new design decoupling it from the
    session-key rotation schedule."""
    was_reached = session.get("reached_vault", False)
    for k in ("user", "role", "login_time"):
        session.pop(k, None)
    rename_vault_table_on_login_timeout()
    if was_reached:
        return redirect(url_for("login"))
    return redirect(url_for("login", reason="logged_out"))


def player_stats():
    """Real numbers for the landing page readout -- not guessed, not
    random. 'Active' means seen via heartbeat in the last 5 minutes and
    not yet flagged; 'solves' is a straight count of players who reached
    the flag. Cheap enough to run on every landing-page load."""
    conn = get_players_db()
    now = time.time()
    active = conn.execute(
        "SELECT COUNT(*) FROM players WHERE flag_reached=0 AND last_heartbeat_at > ?",
        (now - 300,),
    ).fetchone()[0]
    solves = conn.execute("SELECT COUNT(*) FROM players WHERE flag_reached=1").fetchone()[0]
    conn.close()
    return active, solves


@app.route("/", methods=["GET"])
def root():
    if not session.get("pid"):
        pid = secrets.token_hex(8)
        vault_no = random.randint(1, 10)
        now = time.time()
        conn = get_players_db()
        conn.execute(
            "INSERT INTO players (player_id, vault_no, elapsed_seconds, last_heartbeat_at, query_count, max_stars, flag_reached, created_at) "
            "VALUES (?,?,0,?,0,0,0,?)",
            (pid, vault_no, now, now),
        )
        conn.commit()
        conn.close()

        session["pid"] = pid
        session["vault_no"] = vault_no
        return redirect(url_for("root"))

    active_players, total_solves = player_stats()
    return render_template("story.html", theme=vault_theme(), active_players=active_players, total_solves=total_solves)


@app.route("/vault-reveal")
def vault_reveal():
    guard = require_player()
    if guard:
        return guard
    return render_template("vault_reveal.html", vault_no=session["vault_no"])


@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    pid = session.get("pid")
    if not pid:
        return {"ok": False}, 400
    conn = get_players_db()
    row = conn.execute(
        "SELECT last_heartbeat_at, flag_reached, query_count FROM players WHERE player_id=?", (pid,)
    ).fetchone()
    if row and not row["flag_reached"]:
        now = time.time()
        if row["query_count"] > 0:
            gap = min(HEARTBEAT_MAX_GAP, max(0, now - row["last_heartbeat_at"]))
            conn.execute(
                "UPDATE players SET elapsed_seconds = elapsed_seconds + ?, last_heartbeat_at=? WHERE player_id=?",
                (int(gap), now, pid),
            )
        else:
            conn.execute(
                "UPDATE players SET last_heartbeat_at=? WHERE player_id=?", (now, pid)
            )
        conn.commit()
    conn.close()
    return {"ok": True}


@app.route("/login", methods=["GET", "POST"])
def login():
    guard = require_player()
    if guard:
        return guard

    error = None
    if request.method == "POST":
        guard = login_brute_force_guard()
        if guard:
            return guard

        raw_u = request.form.get("username", "")
        raw_p = request.form.get("password", "")
        u = login_waf_filter(raw_u, "username", LOGIN_BYPASS_MODE)
        p = login_waf_filter(raw_p, "password", LOGIN_BYPASS_MODE)

        query = f"SELECT * FROM employees WHERE username='{u}' AND password='{p}'"

        conn = get_db()
        row = None
        failed = False
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.Error:
            error = "\U0001F6A8 Cyber-Sentinel: malformed request rejected by the terminal."
            failed = True
        conn.close()

        bump_query_count()
        if not row:
            failed = True
        if failed:
            if bump_wanted():
                session["wanted_stars"] = 0
                return redirect(url_for("login", reason="mission_failed"))

        if row:
            pid, vault_no = session["pid"], session["vault_no"]
            wanted = session.get("wanted_stars", 0)
            burned = session.get("burned_tokens", [])
            session.clear()
            session["pid"] = pid
            session["vault_no"] = vault_no
            session["wanted_stars"] = wanted
            session["burned_tokens"] = burned
            session.permanent = True
            session["user"] = row["username"]
            session["role"] = row["role"]
            session["login_time"] = time.time()
            session["reached_vault"] = False
            return redirect(url_for("portal"))
        elif not error:
            error = "Access Denied. Badge not recognized."

    reason = request.args.get("reason")
    return render_template("login.html", error=error, reason=reason, theme=vault_theme())


@app.route("/portal")
def portal():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))
    if not login_session_active():
        return handle_login_expiry()

    return render_template(
        "portal.html",
        user=session["user"],
        role=session["role"],
        remaining=login_seconds_remaining(),
        flavor=random_flavor(PORTAL_FLAVOR),
        flavor_pool=PORTAL_FLAVOR,
        special_lines=cj_key_lines(current_xor_key()),
        stars=session.get("wanted_stars", 0),
        theme=vault_theme(),
    )


@app.route("/portal/search", methods=["GET", "POST"])
def search():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))
    if not login_session_active():
        return handle_login_expiry()

    ensure_token_fresh()

    results = None
    error = None
    q_display = ""

    if request.method == "POST":
        raw_q = request.form.get("branch_code", "")
        q = waf_filter(raw_q)
        q_display = q
        query = f"SELECT branch, manager, status FROM branches WHERE branch_code = '{q}'"

        conn = get_db()
        failed = False
        try:
            results = conn.execute(query).fetchall()
        except sqlite3.Error:
            error = "\U0001F6A8 Cyber-Sentinel: malformed request rejected by the terminal."
            failed = True
        conn.close()

        bump_query_count()
        if failed:
            if bump_wanted():
                session["wanted_stars"] = 0
                return redirect(url_for("login", reason="mission_failed"))

    return render_template(
        "search.html",
        results=results,
        error=error,
        q=q_display,
        remaining=login_seconds_remaining(),
        flavor=random_flavor(PORTAL_FLAVOR),
        flavor_pool=PORTAL_FLAVOR,
        special_lines=cj_key_lines(current_xor_key()),
        stars=session.get("wanted_stars", 0),
        theme=vault_theme(),
    )


LINES = [(0, 1, 2), (3, 4, 5), (6, 7, 8), (0, 3, 6), (1, 4, 7), (2, 5, 8), (0, 4, 8), (2, 4, 6)]
REQUIRED_SEQUENCE = [0, 2, 6, 8]


def ttt_winner(b):
    for a, c, d in LINES:
        if b[a] and b[a] == b[c] == b[d]:
            return b[a]
    return None


def ttt_full(b):
    return all(c is not None for c in b)


def ttt_minimax(b, turn):
    w = ttt_winner(b)
    if w == "O":
        return 1, None
    if w == "X":
        return -1, None
    if ttt_full(b):
        return 0, None
    moves = [i for i in range(9) if b[i] is None]
    best_score, best_move = None, None
    for m in moves:
        b2 = b[:]
        b2[m] = turn
        score, _ = ttt_minimax(b2, "O" if turn == "X" else "X")
        if turn == "O":
            if best_score is None or score > best_score:
                best_score, best_move = score, m
        else:
            if best_score is None or score < best_score:
                best_score, best_move = score, m
    return best_score, best_move


def ttt_bot_move(b):
    moves = [i for i in range(9) if b[i] is None]
    best_score, candidates = None, []
    for m in moves:
        b2 = b[:]
        b2[m] = "O"
        score, _ = ttt_minimax(b2, "X")
        if best_score is None or score > best_score:
            best_score, candidates = score, [m]
        elif score == best_score:
            candidates.append(m)
    return min(candidates)


@app.route("/session/<token>")
def game_session(token):
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))

    if not token_is_valid(token) or token in session.get("burned_tokens", []):
        return render_template("invalid_token.html", theme=vault_theme())

    if session.get("game_token") != token:
        reset_game_state()
        session["game_token"] = token
        session["game_started_at"] = time.time()
        session["game_timeout_seconds"] = random.randint(15, 20) * 60
        session["ttt_board"] = [None] * 9
        session["ttt_moves"] = []
        session["ttt_unlocked"] = False
        session["reached_vault"] = True

    if not game_session_active():
        reached_unlock = session.get("ttt_unlocked", False)
        reset_game_state(burn_token=token)
        if reached_unlock:
            return redirect(url_for("hurdle2", token=token))
        return redirect(url_for("login", reason="gameover_timeout"))

    total = session.get("game_timeout_seconds", 900)
    return render_template(
        "session_game.html",
        token=token,
        board=session["ttt_board"],
        remaining=game_seconds_remaining(),
        total=total,
        flavor=random_flavor(GAME_FLAVOR),
        flavor_pool=GAME_FLAVOR,
        moves_made=len(session["ttt_moves"]),
        required_len=len(REQUIRED_SEQUENCE),
        theme=vault_theme(),
    )


@app.route("/session/<token>/move", methods=["POST"])
def game_move(token):
    guard = require_player()
    if guard:
        return guard
    if "user" not in session or session.get("game_token") != token:
        return redirect(url_for("login"))

    if not game_session_active():
        reached_unlock = session.get("ttt_unlocked", False)
        reset_game_state(burn_token=token)
        if reached_unlock:
            return redirect(url_for("hurdle2", token=token))
        return redirect(url_for("login", reason="gameover_timeout"))

    try:
        cell = int(request.form.get("cell", -1))
    except ValueError:
        cell = -1

    board = session["ttt_board"]
    moves = session["ttt_moves"]

    if cell < 0 or cell > 8 or board[cell] is not None:
        return redirect(url_for("game_session", token=token))

    board[cell] = "X"
    moves.append(cell)

    w = ttt_winner(board)
    if w == "X":
        reset_game_state(burn_token=token)
        return redirect(url_for("login", reason="gameover_wrong"))

    if w is None and not ttt_full(board):
        bot_cell = ttt_bot_move(board)
        board[bot_cell] = "O"
        w = ttt_winner(board)

    session["ttt_board"] = board
    session["ttt_moves"] = moves

    if w is None and not ttt_full(board):
        return redirect(url_for("game_session", token=token))

    if w == "O" and moves == REQUIRED_SEQUENCE:
        session["ttt_unlocked"] = True
        return redirect(url_for("hurdle2", token=token))

    reset_game_state(burn_token=token)
    return redirect(url_for("login", reason="gameover_wrong"))


@app.route("/session/<token>/vault", methods=["GET", "POST"])
def hurdle2(token):
    guard = require_player()
    if guard:
        return guard
    if "user" not in session or session.get("game_token") != token:
        return redirect(url_for("login"))
    if not session.get("ttt_unlocked"):
        return redirect(url_for("game_session", token=token))
    if not game_session_active():
        reset_game_state(burn_token=token)
        return redirect(url_for("login", reason="gameover_timeout"))

    error = None
    if request.method == "POST":
        guess = request.form.get("answer", "").strip().upper()
        if guess == H2_PHRASE.upper():
            session["hurdle2_passed"] = True
            return redirect(url_for("finger_print"))
        error = "That's not it. Cyber-Sentinel logs another failed attempt."

    total = session.get("game_timeout_seconds", 900)
    return render_template(
        "hurdle2.html",
        token=token,
        cipher=H2_CIPHER,
        error=error,
        remaining=game_seconds_remaining(),
        total=total,
        flavor=random_flavor(GAME_FLAVOR),
        flavor_pool=GAME_FLAVOR,
        theme=vault_theme(),
    )


@app.route("/diary")
def diary():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("diary.html")


@app.route("/exwordlist")
def exwordlist():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))
    with open(WORDLIST_PATH) as f:
        content = f.read()
    return Response(content, mimetype="text/plain")


@app.route("/cctv_records", methods=["GET", "POST"])
def cctv_records():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        guard = cctv_brute_force_guard()
        if guard:
            return guard

        guess = request.form.get("password", "").strip()
        if guess.lower() == CCTV_PASSWORD.lower():
            session["cctv_verified"] = True
            return redirect(url_for("cctv_records_data"))
        error = "ACCESS DENIED"

    return render_template(
        "cctv_records.html",
        error=error,
        theme=vault_theme(),
    )


@app.route("/cctv_records_data")
def cctv_records_data():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))
    if not session.get("cctv_verified"):
        return redirect(url_for("cctv_records"))

    return render_template(
        "cctv_records_data.html",
        theme=vault_theme(),
        fingerprint_password=FINGERPRINT_PASSWORD,
    )


@app.route("/finger_print", methods=["GET", "POST"])
def finger_print():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))
    if not session.get("hurdle2_passed"):
        return redirect(url_for("portal"))

    error = None
    if request.method == "POST":
        guess = request.form.get("password", "").strip()
        if guess.upper() == FINGERPRINT_PASSWORD.upper():
            session["fingerprint_verified"] = True
            return redirect(url_for("not_a_flag_page"))
        error = "PRINT MISMATCH -- ACCESS DENIED"

    return render_template("finger_print.html", error=error, theme=vault_theme())


@app.route("/Guvf_Vf_Abg_N_Synt_cntr")
def not_a_flag_page():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))
    if not session.get("fingerprint_verified"):
        return redirect(url_for("finger_print"))
    return render_template("This_Is_Not_A_Flag_page.html")


@app.route("/This_Is_A_Flag_page")
def is_a_flag_page():
    guard = require_player()
    if guard:
        return guard
    if "user" not in session:
        return redirect(url_for("login"))
    if not session.get("fingerprint_verified"):
        return redirect(url_for("finger_print"))
    session["decoy_resolved"] = True
    return redirect(url_for("flag_page"))


@app.route("/flag")
def flag_page():
    guard = require_player()
    if guard:
        return guard
    if not session.get("hurdle2_passed"):
        return redirect(url_for("portal"))
    if not session.get("fingerprint_verified"):
        return redirect(url_for("finger_print"))
    if not session.get("decoy_resolved"):
        return redirect(url_for("not_a_flag_page"))

    pid = session["pid"]
    conn = get_players_db()
    row = conn.execute("SELECT * FROM players WHERE player_id=?", (pid,)).fetchone()
    if row and not row["flag_reached"]:
        conn.execute("UPDATE players SET flag_reached=1 WHERE player_id=?", (pid,))
        conn.commit()
        row = conn.execute("SELECT * FROM players WHERE player_id=?", (pid,)).fetchone()
    conn.close()

    mins, secs = divmod(row["elapsed_seconds"], 60)
    stars_display = "\u2605" * row["max_stars"] + "\u2606" * (MAX_STARS - row["max_stars"])

    return render_template(
        "flag.html",
        flag=FLAG,
        time_str=f"{mins:02d}:{secs:02d}",
        queries=row["query_count"],
        stars=stars_display,
    )


@app.route("/logout")
def logout():
    pid = session.get("pid")
    vault_no = session.get("vault_no")
    session.clear()
    if pid:
        session["pid"], session["vault_no"] = pid, vault_no
    return redirect(url_for("root"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
