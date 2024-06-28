import time
import uuid
import shamirs

# https://docs.python.org/3/library/time.html#time.sleep
# https://docs.python.org/3/library/uuid.html#uuid.uuid4
# https://docs.python.org/3/library/random.html#module-random

# Task 1: Generate a 32-Byte Ephemeral ID (EphID) after every 15 sec.

mersenne_prime = (2**607) - 1


def int_encode(s):
    return int.from_bytes(s.encode(), "big")


def string_encode(i):
    return i.to_bytes((i.bit_length() + 7) // 8, "big").decode()


while True:
    time.sleep(1.5)
    alpha_key, bravo_key = str(uuid.uuid4()), str(uuid.uuid4())
    ephemeral_id = alpha_key + "-" + bravo_key
    shares = shamirs.shares(
        int_encode(ephemeral_id), 5, modulus=mersenne_prime, threshold=3
    )

    for share in shares:
        print(share)

    reconstructed_int = shamirs.interpolate(shares[:3])
    reconstructed_ephemeral_id = string_encode(reconstructed_int)

    print(f"Original EphID: {ephemeral_id}")
    print(f"Reconstructed EphID: {reconstructed_ephemeral_id}")
    print("Shares:")
    for share in shares:
        print(share)
    print("\n")
