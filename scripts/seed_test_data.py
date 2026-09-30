#!/usr/bin/env python3
"""Generate synthetic test data for the scanner with Faker.

Every value produced here is fabricated: names, addresses and identifiers come
from Faker, e-mail addresses use the reserved example.* domains, phone numbers
use the fictional 555-01xx range, and the card and SSN values are random
strings that merely satisfy the Luhn / format rules. Nothing is derived from
real people. The same --seed always yields the same data.

    python scripts/seed_test_data.py files --out sample_data
    python scripts/seed_test_data.py postgres            # uses PG* env vars
    python scripts/seed_test_data.py s3 --bucket demo --prefix uploads/ \
        --endpoint-url http://localhost:5000
"""

from __future__ import annotations

import argparse
import json
import os
import string
import sys
from pathlib import Path

try:
    from faker import Faker
except ImportError:  # pragma: no cover
    sys.exit("Faker is required: pip install -r requirements-dev.txt")

CARD_TYPES = ["visa16", "visa19", "mastercard", "amex", "discover", "diners"]


# ---------------------------------------------------------------------------
# Synthetic records
# ---------------------------------------------------------------------------


def make_person(fake: Faker) -> dict[str, str]:
    return {
        "full_name": fake.name(),
        "email": fake.safe_email(),
        "phone": f"+1 ({fake.random_int(200, 989)}) 555-{fake.random_int(100, 199):04d}",
        "ssn": fake.ssn(),
        "card_number": fake.credit_card_number(card_type=fake.random_element(CARD_TYPES)),
        "ip": fake.ipv4_private(),
    }


def format_card(number: str, style: int) -> str:
    """Vary how the same card is written: plain, spaced or dashed."""
    if style == 0 or len(number) not in (16,):
        return number
    sep = " " if style == 1 else "-"
    return sep.join(number[i : i + 4] for i in range(0, 16, 4))


def fake_secret(fake: Faker, length: int, alphabet: str) -> str:
    return "".join(fake.random_element(alphabet) for _ in range(length))


def fake_aws_key(fake: Faker) -> str:
    return "AKIA" + fake_secret(fake, 16, string.ascii_uppercase + string.digits)


def fake_token(fake: Faker, length: int = 40) -> str:
    return fake_secret(fake, length, string.ascii_letters + string.digits)


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


def generate_files(fake: Faker, rows: int) -> dict[str, str]:
    """Relative path -> content for a small mixed data lake."""
    people = [make_person(fake) for _ in range(rows)]
    files: dict[str, str] = {}

    lines = ["id,full_name,email,phone,ssn,card_number,last_ip"]
    for i, p in enumerate(people, 1):
        card = format_card(p["card_number"], i % 3)
        lines.append(f'{i},"{p["full_name"]}",{p["email"]},{p["phone"]},{p["ssn"]},{card},{p["ip"]}')
    files["customers.csv"] = "\n".join(lines) + "\n"

    notes = []
    for p in people[: max(rows // 2, 3)]:
        notes.append(
            f"Call back {p['full_name']} on {p['phone']}; confirmed by email {p['email']}. "
            f"Customer read out card {format_card(p['card_number'], 1)} over the phone."
        )
        notes.append(f"Identity check passed, SSN {p['ssn']} matches the file.")
        notes.append(fake.sentence(nb_words=12))
    files["support_notes.txt"] = "\n".join(notes) + "\n"

    log = []
    for i, p in enumerate(people[: max(rows, 6)], 1):
        stamp = f"2024-05-{(i % 27) + 1:02d} 10:{i % 60:02d}:00"
        log.append(f"{stamp} INFO  login ok user={p['email']} ip={p['ip']}")
        if i % 4 == 0:
            log.append(f"{stamp} DEBUG payment payload card={p['card_number']} amount={fake.random_int(5, 900)}.00")
        if i % 5 == 0:
            log.append(f"{stamp} WARN  retry order={fake.random_int(10**15, 10**16 - 1)} status=timeout")
    files["logs/app.log"] = "\n".join(log) + "\n"

    orders = [
        {
            "order_id": f"ORD-{fake.random_int(100000, 999999)}",
            "customer": {"name": p["full_name"], "email": p["email"]},
            "payment": {"card": p["card_number"], "amount": fake.random_int(5, 900)},
            "note": fake.sentence(nb_words=8),
        }
        for p in people[: max(rows // 2, 3)]
    ]
    files["exports/orders.json"] = json.dumps(orders, indent=2) + "\n"

    sql = ["CREATE TABLE members (id int, email text, ssn text);"]
    for i, p in enumerate(people[: max(rows // 2, 3)], 1):
        sql.append(f"INSERT INTO members VALUES ({i}, '{p['email']}', '{p['ssn']}');")
    files["exports/members_dump.sql"] = "\n".join(sql) + "\n"

    files["ops/deploy_notes.txt"] = (
        "Deployment checklist\n"
        f"aws_access_key_id = {fake_aws_key(fake)}\n"
        f"aws_secret_access_key = {fake_token(fake)}\n"
        f"service_token: {fake_token(fake, 32)}\n"
        "Release owner: ops@example.org\n"
    )

    # Content that looks sensitive but is not - proves the false-positive filters.
    files["clean/false_positives.txt"] = (
        "Order reference 1234567812345678 shipped (fails the Luhn check)\n"
        "Unix timestamp 1700000000000 and build 20240501123045\n"
        "Retina asset logo@2x.png and contact user@host.invalidtld\n"
        "Version 1.2.3, commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b\n"
        "Invalid SSN 000-12-3456 and 666-45-6789\n"
    )
    files["clean/readme.txt"] = fake.paragraph(nb_sentences=4) + "\n"
    return files


def cmd_files(args: argparse.Namespace) -> None:
    fake = make_faker(args.seed)
    out = Path(args.out)
    files = generate_files(fake, args.rows)
    for rel, content in files.items():
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    print(f"wrote {len(files)} synthetic files to {out}/")


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------

DDL = """
DROP TABLE IF EXISTS support_tickets, orders, audit_log, users CASCADE;

CREATE TABLE users (
    id          serial PRIMARY KEY,
    full_name   text NOT NULL,
    email       text,
    phone       text,
    ssn         text,
    card_number text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE orders (
    id          serial PRIMARY KEY,
    user_id     integer REFERENCES users (id),
    amount      numeric(10, 2) NOT NULL,
    notes       text,
    shipping_ip text
);

CREATE TABLE support_tickets (
    ticket_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    body      text NOT NULL,
    metadata  jsonb
);

CREATE TABLE audit_log (
    id       serial PRIMARY KEY,
    action   text NOT NULL,
    actor_ip text
);
"""


def cmd_postgres(args: argparse.Namespace) -> None:
    import psycopg

    fake = make_faker(args.seed)
    people = [make_person(fake) for _ in range(args.rows)]

    with psycopg.connect(connect_timeout=10) as conn:  # PG* environment variables
        with conn.cursor() as cur:
            cur.execute(DDL)
            cur.executemany(
                "INSERT INTO users (full_name, email, phone, ssn, card_number) VALUES (%s, %s, %s, %s, %s)",
                [
                    (
                        p["full_name"],
                        p["email"],
                        p["phone"],
                        p["ssn"],
                        format_card(p["card_number"], i % 3),
                    )
                    for i, p in enumerate(people)
                ],
            )
            cur.executemany(
                "INSERT INTO orders (user_id, amount, notes, shipping_ip) VALUES (%s, %s, %s, %s)",
                [
                    (
                        i,
                        fake.random_int(5, 900),
                        # every 10th note carries a card number typed by an agent
                        f"Paid with card {p['card_number']}" if i % 10 == 0 else fake.sentence(nb_words=6),
                        p["ip"],
                    )
                    for i, p in enumerate(people, 1)
                ],
            )
            cur.executemany(
                "INSERT INTO support_tickets (body, metadata) VALUES (%s, %s::jsonb)",
                [
                    (
                        f"{fake.sentence(nb_words=8)} Reach me at {p['email']}.",
                        json.dumps({"contact": {"email": p["email"], "phone": p["phone"]}}),
                    )
                    for p in people[: max(args.rows // 4, 3)]
                ],
            )
            cur.executemany(
                "INSERT INTO audit_log (action, actor_ip) VALUES (%s, %s)",
                [(fake.random_element(["login", "logout", "export"]), p["ip"]) for p in people],
            )
    print(f"seeded PostgreSQL with {args.rows} users and related tables")


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------


def cmd_s3(args: argparse.Namespace) -> None:
    import boto3
    from botocore.exceptions import ClientError

    fake = make_faker(args.seed)
    files = generate_files(fake, args.rows)
    client = boto3.client("s3", endpoint_url=args.endpoint_url or os.environ.get("AWS_ENDPOINT_URL"))
    try:
        client.head_bucket(Bucket=args.bucket)
    except ClientError:
        client.create_bucket(Bucket=args.bucket)
    prefix = args.prefix
    for rel, content in files.items():
        client.put_object(Bucket=args.bucket, Key=f"{prefix}{rel}", Body=content.encode("utf-8"))
    print(f"uploaded {len(files)} synthetic objects to s3://{args.bucket}/{prefix}")


# ---------------------------------------------------------------------------


def make_faker(seed: int) -> Faker:
    Faker.seed(seed)
    return Faker("en_US")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=42, help="Faker seed (default: 42)")
    parser.add_argument("--rows", type=int, default=50, help="number of synthetic people (default: 50)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_files = sub.add_parser("files", help="write sample files to a directory")
    p_files.add_argument("--out", default="sample_data")
    p_files.set_defaults(func=cmd_files)

    p_pg = sub.add_parser("postgres", help="create and fill demo tables (PG* env vars)")
    p_pg.set_defaults(func=cmd_postgres)

    p_s3 = sub.add_parser("s3", help="upload the sample files to a bucket")
    p_s3.add_argument("--bucket", required=True)
    p_s3.add_argument("--prefix", default="uploads/")
    p_s3.add_argument("--endpoint-url", help="S3-compatible endpoint (moto, MinIO, LocalStack)")
    p_s3.set_defaults(func=cmd_s3)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
