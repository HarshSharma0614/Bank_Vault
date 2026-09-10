"""
Ganton Bank (and friends) — Vault Database Initializer
Rebuilds ctf.db, the flag, the hurdle-2 cipher, the CCTV password, and the
1200-line ex-wordlist. Safe to re-run — wipes and rebuilds everything
EXCEPT the players table if it already exists with progress (see below).
"""

import sqlite3
import os
import base64
import secrets
import string
import random

HERE = os.path.dirname(__file__)
DB_PATH = os.path.join(HERE, "ctf.db")
PLAYERS_DB_PATH = os.path.join(HERE, "players.db")
FLAG_PATH = os.path.join(HERE, ".flag")
HURDLE2_PATH = os.path.join(HERE, ".hurdle2")
EXNAME_PATH = os.path.join(HERE, ".exname")
FINGERPRINT_PATH = os.path.join(HERE, ".fingerprint")
WORDLIST_PATH = os.path.join(HERE, "wordlist_export.txt")


def rand_pw(n=22):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(n))


FP_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def rand_fp_code(n=8):
    return "".join(secrets.choice(FP_ALPHABET) for _ in range(n))


def xor_encrypt(plaintext: str, key: str) -> str:
    data = plaintext.encode()
    k = key.encode()
    out = bytes(b ^ k[i % len(k)] for i, b in enumerate(data))
    return base64.b64encode(out).decode()


def caesar_encrypt(plaintext: str, shift: int) -> str:
    out = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


FIRST_NAMES = [
    "Aaliyah","Abigail","Adriana","Alexis","Alice","Amara","Amber","Amelia","Amy","Anastasia",
    "Angela","Anita","Anna","April","Ashley","Aubrey","Audrey","Aurora","Autumn","Ava",
    "Barbara","Beatrice","Bella","Bianca","Brianna","Bridget","Brooke","Camila","Candace","Carla",
    "Carmen","Carol","Caroline","Catalina","Catherine","Cecilia","Celeste","Charlotte","Chloe","Christina",
    "Claire","Clara","Claudia","Coral","Courtney","Crystal","Daisy","Dakota","Daniela","Danielle",
    "Deborah","Delilah","Denise","Diana","Dominique","Donna","Dorothy","Eden","Elena","Eliana",
    "Elizabeth","Ella","Ellie","Elsie","Emily","Emma","Erica","Erin","Esmeralda","Esperanza",
    "Estelle","Eva","Evelyn","Faith","Farrah","Fiona","Flora","Frances","Gabriela","Gemma",
    "Genesis","Georgia","Giselle","Gloria","Grace","Gracie","Hailey","Hannah","Harmony","Hazel",
    "Heather","Helena","Holly","Hope","Ingrid","Irene","Isabel","Isabella","Isla","Ivy",
    "Jacqueline","Jade","Jamie","Jasmine","Jazmin","Jenna","Jennifer","Jessica","Jocelyn","Jordan",
    "Josephine","Judith","Julia","Juliana","June","Kaitlyn","Karen","Karina","Katherine","Katie",
    "Kaylee","Kelly","Kendall","Kennedy","Kiara","Kimberly","Kylie","Lacey","Lana","Laura",
    "Lauren","Layla","Leah","Leilani","Lena","Leslie","Lila","Lillian","Lily","Linda",
    "Lisa","Lola","London","Lucia","Lucille","Lucy","Luna","Lydia","Mackenzie","Madeline",
    "Madison","Maria","Mariah","Marina","Marisol","Mary","Maya","Megan","Melanie","Melissa",
    "Mia","Michelle","Mikayla","Mila","Miranda","Molly","Monica","Morgan","Nadia","Naomi",
    "Natalia","Natalie","Nevaeh","Nicole","Nina","Noelle","Nora","Norah","Olivia","Paige",
    "Paloma","Paola","Paris","Patricia","Payton","Penelope","Peyton","Phoebe","Piper","Priscilla",
    "Rachel","Raquel","Rebecca","Regina","Renata","Rita","Riley","Rosa","Rose","Ruby",
    "Aanya","Aditi","Aishwarya","Alisha","Ananya","Anika","Anjali","Anushka","Aparna","Arpita",
    "Bhavya","Chandni","Deepika","Divya","Esha","Gauri","Ishaani","Ishita","Jhanvi","Kavya",
    "Kiran","Kritika","Lakshmi","Manasi","Meera","Nandini","Neha","Nikita","Ojasvi","Pallavi",
    "Pooja","Preeti","Priya","Radhika","Riya","Ritika","Sakshi","Sanjana","Sanya","Shreya",
    "Simran","Sneha","Swati","Tanvi","Tara","Trisha","Urvi","Vaishnavi","Vanshika","Yamini",
]

LAST_NAMES = [
    "Alvarez","Anderson","Bailey","Baker","Barnes","Bell","Bennett","Brooks","Brown","Bryant",
    "Butler","Campbell","Carter","Castillo","Chavez","Clark","Coleman","Collins","Cooper","Cox",
    "Cruz","Diaz","Dixon","Edwards","Ellis","Evans","Fisher","Flores","Ford","Foster",
    "Garcia","Gomez","Gonzalez","Gray","Green","Griffin","Gutierrez","Hall","Harris","Hayes",
    "Henderson","Hernandez","Hill","Howard","Hughes","Jackson","James","Jenkins","Johnson","Jones",
    "Jordan","Kelly","King","Long","Lopez","Martin","Martinez","Mendoza","Miller","Mitchell",
    "Moore","Morales","Morgan","Morris","Murphy","Myers","Nelson","Nguyen","Ortiz","Owens",
    "Parker","Patterson","Perez","Perry","Peterson","Phillips","Powell","Price","Ramirez","Ramos",
    "Reed","Reyes","Richardson","Rivera","Roberts","Robinson","Rodriguez","Rogers","Ross","Russell",
    "Sanchez","Sanders","Scott","Simmons","Smith","Stewart","Sullivan","Taylor","Thomas","Thompson",
    "Torres","Turner","Vasquez","Wallace","Walker","Ward","Washington","Watson","Weaver","White",
    "Agarwal","Banerjee","Bansal","Bhatt","Bose","Chatterjee","Chauhan","Chopra","Das","Desai",
    "Dubey","Ghosh","Gowda","Gupta","Hegde","Iyengar","Iyer","Jain","Jaiswal","Joshi",
    "Kapoor","Kaur","Khanna","Kulkarni","Kumar","Malhotra","Mehta","Mishra","Mukherjee","Nair",
    "Nayar","Pandey","Patel","Rao","Rastogi","Reddy","Saxena","Sengupta","Shah","Sharma",
    "Singh","Trivedi","Varma","Verma","Yadav",
]


VJ_FIRST_NAMES = ["Vaishnavi", "Vanshika"]
VJ_LAST_NAMES = ["Jain", "Jaiswal", "Joshi"]


def gen_wordlist(real_name, count=1200):
    names = set()
    while len(names) < count - 1:
        n = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        if n.lower() != real_name.lower():
            names.add(n)
    names = list(names)

    def is_vj(n):
        first, _, last = n.partition(" ")
        return first.startswith("V") and last.startswith("J")

    names = [n for n in names if not is_vj(n)]

    decoy_pool = [
        f"{f} {l}" for f in VJ_FIRST_NAMES for l in VJ_LAST_NAMES
        if f"{f} {l}".lower() != real_name.lower()
    ]
    random.shuffle(decoy_pool)
    decoys = decoy_pool[: random.randint(4, min(6, len(decoy_pool)))]

    while len(names) + len(decoys) > count - 1:
        names.pop()
    names.extend(decoys)

    random.shuffle(names)
    insert_at = random.randint(0, len(names))
    names.insert(insert_at, real_name)
    return names


def build(reset_players=False):
    pconn = sqlite3.connect(PLAYERS_DB_PATH)

    cols = [r[1] for r in pconn.execute("PRAGMA table_info(players)").fetchall()]
    if cols and "player_id" not in cols:
        pconn.execute("DROP TABLE players")

    pconn.execute(
        """CREATE TABLE IF NOT EXISTS players (
            player_id TEXT PRIMARY KEY,
            vault_no INTEGER NOT NULL,
            elapsed_seconds INTEGER NOT NULL DEFAULT 0,
            last_heartbeat_at REAL NOT NULL,
            query_count INTEGER NOT NULL DEFAULT 0,
            max_stars INTEGER NOT NULL DEFAULT 0,
            flag_reached INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )"""
    )
    if reset_players:
        pconn.execute("DELETE FROM players")
    pconn.commit()
    pconn.close()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    for tbl in ("employees", "branches"):
        c.execute(f"DROP TABLE IF EXISTS {tbl}")
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'vt_%'")
    for row in c.fetchall():
        c.execute(f"DROP TABLE IF EXISTS {row[0]}")
    c.execute("DROP TABLE IF EXISTS vault_secrets")

    c.execute(
        """CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )"""
    )
    admin_pw = rand_pw()
    cj_pw = rand_pw()
    smoke_pw = rand_pw()
    c.executemany(
        "INSERT INTO employees (id, username, password, role) VALUES (?,?,?,?)",
        [
            (1, "admin", admin_pw, "Site Manager"),
            (2, "cj", cj_pw, "Undercover Asset"),
            (3, "big_smoke", smoke_pw, "Person of Interest"),
        ],
    )

    c.execute(
        """CREATE TABLE branches (
            id INTEGER PRIMARY KEY,
            branch_code TEXT NOT NULL,
            branch TEXT NOT NULL,
            manager TEXT NOT NULL,
            status TEXT NOT NULL
        )"""
    )
    c.executemany(
        "INSERT INTO branches (branch_code, branch, manager, status) VALUES (?,?,?,?)",
        [
            ("LS01", "Los Santos - Ganton Site", "Mr. Reeves", "ACTIVE"),
            ("LS02", "Los Santos - Downtown Site", "Ms. Falcon", "ACTIVE"),
            ("SF01", "San Fierro Site", "Mr. Chen", "CLOSED"),
            ("LV01", "Las Venturas Site", "Mr. Ashworth", "ACTIVE"),
        ],
    )

    c.execute(
        """CREATE TABLE vault_secrets (
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            data TEXT NOT NULL
        )"""
    )
    placeholder_key = secrets.token_urlsafe(9)
    placeholder_token = secrets.token_hex(8)
    placeholder_enc = xor_encrypt(placeholder_token, placeholder_key)
    c.executemany(
        "INSERT INTO vault_secrets (label, data) VALUES (?,?)",
        [
            ("vault_camera_schedule", "Rotates every 45 seconds, guard shift changes at 02:00"),
            ("safe_combo_decoy", "12-36-89 (this is fake, Sweet warned CJ about this one)"),
            ("session_token_enc", placeholder_enc),
            ("ops_note", "Tenpenny's been asking questions about this site again."),
        ],
    )

    conn.commit()
    conn.close()

    flag = "CTF{4h_sh1t_h3r3_w3_g0_4g41n_" + secrets.token_hex(4) + "}_M4G1C14N"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

    shift = secrets.randbelow(20) + 3
    phrase = "GROVE STREET FOREVER"
    cipher = caesar_encrypt(phrase, shift)
    with open(HURDLE2_PATH, "w") as f:
        f.write(f"{shift}\n{phrase}\n{cipher}\n")

    real_ex_name = "Vanshmita Jaiswara"
    with open(EXNAME_PATH, "w") as f:
        f.write(real_ex_name)

    wordlist = gen_wordlist(real_ex_name, 1200)
    with open(WORDLIST_PATH, "w") as f:
        f.write("\n".join(wordlist) + "\n")

    fp_code = rand_fp_code()
    with open(FINGERPRINT_PATH, "w") as f:
        f.write(fp_code)

    print("[+] ctf.db built.")
    print("[+] .flag:", flag)
    print("[+] .hurdle2 shift/phrase/cipher:", shift, phrase, cipher)
    print("[+] .exname (CCTV password):", real_ex_name)
    print("[+] .fingerprint (finger_print override code):", fp_code)
    print("[+] wordlist_export.txt: 1200 lines written")
    print("[+] admin password (unused by design):", admin_pw)


if __name__ == "__main__":
    build()
