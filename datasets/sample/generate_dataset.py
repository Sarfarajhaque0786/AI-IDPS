"""
Generates a small, safe, synthetic traffic dataset for local ML training.
No real network capture involved - purely generated data mimicking
patterns of BENIGN / DoS / Probe / Brute Force / Bot traffic,
loosely inspired by CIC-IDS2017 / UNSW-NB15 style features.
"""
import random
import csv
import os

random.seed(42)  # reproducibility

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "traffic_sample.csv")

ROWS_PER_CLASS = 400


def gen_benign():
    return dict(
        packet_count=random.randint(5, 50),
        byte_count=random.randint(500, 5000),
        protocol=random.choice(["TCP", "UDP"]),
        source_port=random.randint(1024, 65535),
        destination_port=random.choice([80, 443]),
        label="BENIGN",
    )


def gen_dos():
    return dict(
        packet_count=random.randint(500, 1500),
        byte_count=random.randint(50000, 200000),
        protocol="TCP",
        source_port=random.randint(1024, 65535),
        destination_port=random.choice([80, 443, 8080]),
        label="DoS",
    )


def gen_probe():
    return dict(
        packet_count=random.randint(1, 20),
        byte_count=random.randint(40, 1500),
        protocol=random.choice(["UDP", "ICMP"]),
        source_port=random.randint(1024, 65535),
        destination_port=random.randint(1, 1023),
        label="Probe",
    )


def gen_brute_force():
    return dict(
        packet_count=random.randint(1, 8),
        byte_count=random.randint(50, 400),
        protocol="TCP",
        source_port=random.randint(1024, 65535),
        destination_port=random.choice([22, 3389]),
        label="Brute Force",
    )


def gen_bot():
    return dict(
        packet_count=random.randint(10, 30),
        byte_count=random.randint(200, 800),
        protocol="TCP",
        source_port=random.randint(1024, 65535),
        destination_port=443,
        label="Bot",
    )


def main():
    generators = [gen_benign, gen_dos, gen_probe, gen_brute_force, gen_bot]
    rows = []
    for gen in generators:
        for _ in range(ROWS_PER_CLASS):
            rows.append(gen())
    random.shuffle(rows)

    fieldnames = ["packet_count", "byte_count", "protocol", "source_port", "destination_port", "label"]
    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} rows -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()