import time
import base64
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
        enc_t, dec_t = crypto_time(enc, dec)
        ins_t = insert_data(enc)
        stor = storage_mb()
        q_t = query_decrypt_time(dec)

        rows.append({
            "config": label,
            "repeat": r + 1,
            "enc_time_s": enc_t,
            "dec_time_s": dec_t,
            "insert_time_s": ins_t,
            "query+decrypt_time_s": q_t,
            "storage_mb": stor
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

    print("\n=== RAW RESULTS ===")
    print(df)

    print("\n=== SUMMARY (MEAN) ===")
    print(summary)

    df.to_csv("mongodb_perf_raw.csv", index=False)
    summary.to_csv("mongodb_perf_summary.csv", index=False)
    print("\nSaved: mongodb_perf_raw.csv, mongodb_perf_summary.csv")


if __name__ == "__main__":
    main()