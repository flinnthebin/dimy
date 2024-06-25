import random
from sympy import symbols, Eq, solve, Mod

# Define a prime number greater than the maximum secret value
PRIME = 208351617316091241234326746312124448251235562226470491514186331217050270460481


# Function to generate a random polynomial of degree k-1
def generate_polynomial(secret, k):
    coeffs = [secret] + [random.randrange(0, PRIME) for _ in range(k - 1)]
    return coeffs


# Function to evaluate polynomial at a given x value
def evaluate_polynomial(coeffs, x):
    return sum([coeff * (x**i) for i, coeff in enumerate(coeffs)]) % PRIME


# Function to generate shares
def generate_shares(secret, n, k):
    coeffs = generate_polynomial(secret, k)
    shares = [(i, evaluate_polynomial(coeffs, i)) for i in range(1, n + 1)]
    return shares


# Function to perform Lagrange interpolation
def lagrange_interpolation(x, x_s, y_s):
    k = len(x_s)
    total = 0
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        li = 1
        for j in range(k):
            if i != j:
                xj = x_s[j]
                li *= (x - xj) * pow(xi - xj, -1, PRIME)
                li %= PRIME
        total += yi * li
        total %= PRIME
    return total


# Function to reconstruct the secret
def reconstruct_secret(shares, k):
    x_s, y_s = zip(*shares)
    secret = lagrange_interpolation(0, x_s, y_s)
    return secret


# Example usage
if __name__ == "__main__":
    secret = 12345  # Example secret
    n = 5  # Total number of shares
    k = 3  # Threshold number of shares

    # Generate shares
    shares = generate_shares(secret, n, k)
    print(f"Generated shares: {shares}")

    # Select 3 shares to reconstruct the secret
    selected_shares = shares[:3]
    print(f"Selected shares for reconstruction: {selected_shares}")

    # Reconstruct the secret
    reconstructed_secret = reconstruct_secret(selected_shares, k)
    print(f"Reconstructed secret: {reconstructed_secret}")
