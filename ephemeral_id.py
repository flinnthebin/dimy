import time
import uuid
import shamir_secret

# https://docs.python.org/3/library/time.html#time.sleep
# https://docs.python.org/3/library/uuid.html#uuid.uuid4
# https://docs.python.org/3/library/random.html#module-random

# Task 1: Generate a 32-Byte Ephemeral ID (EphID) after every 15 sec.
while True:
    time.sleep(1.5)
    alpha_key, bravo_key = str(uuid.uuid4()), str(uuid.uuid4())
    ephemeral_id = alpha_key + "-" + bravo_key
