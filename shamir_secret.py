import random
from sympy import symbols, eq, solve

mersenne_prime = 2**521 - 1


def k_minus_1_coefficients(k):
    return [random.randint(0, mersenne_prime - 1) for _ in range(k - 1)]


def evaluate_at_x(coefficients, x):
    result = 0
    for i, coef in enumerate(coefficients):
        result += coef * (x**i)
    return result % mersenne_prime


def spawn_shares(secret, k, n):
    secret_int = int.from_bytes(secret.encode("utf-8"), byteorder="big")
    coefficients = k_minus_1_coefficients(k) + secret_int

    shares = []
    for i in range(1, n + 1):
        x = i
        y = evaluate_at_x(coefficients, x)
        shares.append((x, y))

    return shares


# Function to perform Lagrange interpolation to recover the secret
def lagrange_interpolation(shares):
    def basis_polynomial(j, x):
        result = 1
        for m in range(len(shares)):
            if m != j:
                result *= (x - shares[m][0]) * pow(
                    shares[j][0] - shares[m][0], -1, PRIME
                )
                result %= mersenne_prime
        return result

    x = symbols("x")
    secret_int = 0
    for j in range(len(shares)):
        bj = basis_polynomial(j, 0)
        secret_int += shares[j][1] * bj
        secret_int %= PRIME

    secret_bytes = secret_int.to_bytes(
        (secret_int.bit_length() + 7) // 8, byteorder="big"
    )
    return secret_bytes.decode("utf-8")


# Example usage:
keys = [
    "9292dfac-ab46-4658-91fe-4908ba6dd9c6-6a3e64a7-523a-484e-ba1a-5e31303d6787",
    "dca07021-9ea3-40fc-b2dc-76166bbb951a-a3202ad9-a057-4b1b-ba26-2c1ac684f6ba",
    "021cdabc-b64f-41c3-bc4a-49f22df933be-030280ec-8035-4b58-a05b-83f735b6b908",
    "10c5f60c-0ede-46d8-b745-45fc14082546-fc0f9a37-5e82-463f-b062-5808d52b5e30",
]

k = 3
n = 5
all_shares = []

for key in keys:
    shares = create_shares(key, k, n)
    all_shares.append(shares)

# Example of reconstructing a secret
reconstructed_secret = lagrange_interpolation(all_shares[0][:k])
print(f"Reconstructed Secret: {reconstructed_secret}")
