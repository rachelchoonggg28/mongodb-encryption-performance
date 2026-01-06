# MongoDB Encryption Performance Evaluation

This repository contains the experimental code used to evaluate the performance impact of encryption mechanisms in a NoSQL DBMS environment using MongoDB.

## Environment
- OS: macOS
- Database: MongoDB Community Edition
- Language: Python 3.12
- Libraries: PyMongo, PyCryptodome, Pandas

## Encryption Algorithms
- AES (128-bit, CBC)
- DES (56-bit, CBC)
- 3DES (168-bit, CBC)
- Plaintext baseline

## Performance Metrics
- Encryption time
- Decryption time
- Data insertion time
- Query execution time
- Storage overhead

## How to Run
```bash
pip install pymongo pycryptodome pandas
python mongodb_perf.py