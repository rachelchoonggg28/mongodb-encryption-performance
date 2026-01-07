import time
import base64
import os
import psutil
import pandas as pd
from pymongo import MongoClient

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes


# =======================
# MongoDB Connection
# =======================
client = MongoClient("mongodb://127.0.0.1:27017/", serverSelectionTimeoutMS=5000)
db = client["perf_test"]
collection = db["records"]


# =======================
# Process Monitor (CPU/RAM)
# =======================
PROC = psutil.Process(os.getpid())

def _cpu_time_seconds() -> float:
    # total CPU time used by this Python process
    ct = PROC.cpu_times()
    return float(ct.user + ct.system)

def _rss_bytes() -> int:
    # resident memory (RAM) used by this Python process
    return int(PROC.memory_info().rss)

def measure_stage(fn, *args, warmup_sec: float = 0.05):
    """
    Run fn(*args) and measure:
    - wall_time_s
    - cpu_time_s (process CPU time)
    - cpu_util_pct (cpu_time / wall_time * 100; can exceed 100 on multi-core)
    - rss_delta_mb (end_rss - start_rss)
    Returns: (fn_result, metrics_dict)
    """
    # small warmup to stabilize percent sampling/OS scheduling
    time.sleep(warmup_sec)

    cpu0 = _cpu_time_seconds()
    mem0 = _rss_bytes()
    t0 = time.perf_counter()

    result = fn(*args)

    t1 = time.perf_counter()
    cpu1 = _cpu_time_seconds()
    mem1 = _rss_bytes()

    wall = t1 - t0
    cpu = cpu1 - cpu0
    cpu_util = (cpu / wall * 100.0) if wall > 0 else 0.0
    rss_delta_mb = (mem1 - mem0) / (1024 * 1024)

    metrics = {
        "wall_time_s": wall,
        "cpu_time_s": cpu,
        "cpu_util_pct": cpu_util,
        "rss_delta_mb": rss_delta_mb,
    }
    return result, metrics


# =======================
# Crypto Keys
# =======================
AES_KEY = get_random_bytes(16)   # AES-128
DES_KEY = get_random_bytes(8)    # DES

def gen_3des_key():
    while True:
        key = DES3.adjust_key_parity(get_random_bytes(24))
        try:
            DES3.new(key, DES3.MODE_CBC)
            return key
        except ValueError:
            pass

TDES_KEY = gen_3des_key()


# =======================
# Encryption / Decryption
# =======================
def aes_encrypt(data: str) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct).decode()

def aes_decrypt(enc: str) -> str:
    raw = base64.b64decode(enc)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def des_encrypt(data: str) -> str:
    cipher = DES.new(DES_KEY, DES.MODE_CBC)
    ct = cipher.encrypt(pad(data.encode(), DES.block_size))
    return base64.b64encode(cipher.iv + ct).decode()

def des_decrypt(enc: str) -> str:
    raw = base64.b64decode(enc)
    iv, ct = raw[:8], raw[8:]
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size).decode()

def tdes_encrypt(data: str) -> str:
    cipher = DES3.new(TDES_KEY, DES3.MODE_CBC)
    ct = cipher.encrypt(pad(data.encode(), DES3.block_size))
    return base64.b64encode(cipher.iv + ct).decode()

def tdes_decrypt(enc: str) -> str:
    raw = base64.b64decode(enc)
    iv, ct = raw[:8], raw[8:]
    cipher = DES3.new(TDES_KEY, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES3.block_size).decode()

def plain_encrypt(x: str) -> str:
    return x

def plain_decrypt(x: str) -> str:
    return x


# =======================
# Performance Metrics
# =======================
def storage_mb():
    stats = db.command("collstats", "records")
    return stats["storageSize"] / (1024 * 1024)

def crypto_time(enc, dec, N=5000):
    start = time.perf_counter()
    enc_list = [enc("0123456789") for _ in range(N)]
    enc_t = time.perf_counter() - start

    start = time.perf_counter()
    for s in enc_list:
        dec(s)
    dec_t = time.perf_counter() - start
    return enc_t, dec_t

def insert_data(enc, N=3000, batch=200):
    collection.delete_many({})
    start = time.perf_counter()
    docs = []

    for i in range(N):
        docs.append({
            "name": enc(f"User{i}"),
            "phone": enc("0123456789"),
            "amount": i * 10
        })
        if len(docs) == batch:
            collection.insert_many(docs)
            docs = []
    if docs:
        collection.insert_many(docs)

    return time.perf_counter() - start

def query_decrypt_time(dec, N=800):
    start = time.perf_counter()
    for doc in collection.find({}, {"phone": 1}).limit(N):
        dec(doc["phone"])
    return time.perf_counter() - start


# =======================
# Run Experiment
# =======================
def run_config(label, enc, dec, repeats=3):
    rows = []
    for r in range(repeats):

        # --- Crypto stage (CPU/RAM measured) ---
        (enc_dec_times, crypto_m) = measure_stage(lambda: crypto_time(enc, dec))
        enc_t, dec_t = enc_dec_times

        # --- Insert stage (CPU/RAM measured) ---
        (ins_t, insert_m) = measure_stage(lambda: insert_data(enc))

        # --- Storage stage (fast, no need CPU/RAM) ---
        stor = storage_mb()

        # --- Query+Decrypt stage (CPU/RAM measured) ---
        (q_t, query_m) = measure_stage(lambda: query_decrypt_time(dec))

        rows.append({
            "config": label,
            "repeat": r + 1,

            # existing metrics
            "enc_time_s": enc_t,
            "dec_time_s": dec_t,
            "insert_time_s": ins_t,
            "query+decrypt_time_s": q_t,
            "storage_mb": stor,

            # NEW: CPU/RAM metrics per stage
            "crypto_cpu_time_s": crypto_m["cpu_time_s"],
            "crypto_cpu_util_pct": crypto_m["cpu_util_pct"],
            "crypto_rss_delta_mb": crypto_m["rss_delta_mb"],

            "insert_cpu_time_s": insert_m["cpu_time_s"],
            "insert_cpu_util_pct": insert_m["cpu_util_pct"],
            "insert_rss_delta_mb": insert_m["rss_delta_mb"],

            "query_cpu_time_s": query_m["cpu_time_s"],
            "query_cpu_util_pct": query_m["cpu_util_pct"],
            "query_rss_delta_mb": query_m["rss_delta_mb"],
        })
    return rows


def main():
    try:
        collection.count_documents({})
    except Exception:
        print("❌ Cannot connect to MongoDB. Is it running?")
        return

    configs = [
        ("PLAIN", plain_encrypt, plain_decrypt),
        ("AES", aes_encrypt, aes_decrypt),
        ("DES", des_encrypt, des_decrypt),
        ("3DES", tdes_encrypt, tdes_decrypt),
    ]

    all_rows = []
    for label, enc, dec in configs:
        print(f"Running {label} ...")
        all_rows += run_config(label, enc, dec)

    df = pd.DataFrame(all_rows)
    summary = df.groupby("config").mean(numeric_only=True).reset_index()

    # OPTIONAL: compute overhead vs plaintext (mean)
    base = summary[summary["config"] == "PLAIN"].iloc[0]
    overhead = summary.copy()
    metric_cols = [c for c in overhead.columns if c not in ["config"]]
    for c in metric_cols:
        overhead[c] = overhead[c] - base[c]
    overhead.insert(1, "baseline", "PLAIN")

    print("\n=== RAW RESULTS ===")
    print(df)

    print("\n=== SUMMARY (MEAN) ===")
    print(summary)

    print("\n=== OVERHEAD vs PLAIN (MEAN DIFF) ===")
    print(overhead)

    df.to_csv("mongodb_perf_raw.csv", index=False)
    summary.to_csv("mongodb_perf_summary.csv", index=False)
    overhead.to_csv("mongodb_perf_overhead_vs_plain.csv", index=False)
    print("\nSaved: mongodb_perf_raw.csv, mongodb_perf_summary.csv, mongodb_perf_overhead_vs_plain.csv")


if __name__ == "__main__":
    main()