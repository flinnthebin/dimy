import time
import uuid

# https://docs.python.org/3/library/time.html
# https://docs.python.org/3/library/uuid.html

# Task 1: Generate a 32-Byte Ephemeral ID (EphID) after every 15 sec.
while (True):
    time.sleep(1)
    alpha_key, bravo_key = str(uuid.uuid4()), str(uuid.uuid4())
    final_key = alpha_key + "-" + bravo_key

    # some logic to send this 32-byte Ephemeral ID somewhere
