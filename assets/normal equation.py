import numpy as np
import matplotlib.pyplot as plt
import time

def normal_equation_time(X, y):
    start = time.time()
    theta = np.linalg.solve(X.T @ X, X.T @ y)
    return time.time() - start

def stochastic_gradient_descent_time(X, y, lr=0.01, n_epochs=10):
    start = time.time()
    m, n = X.shape
    theta = np.random.randn(n)
    for epoch in range(n_epochs):
        indices = np.random.permutation(m)
        for i in indices:
            xi = X[i:i+1]
            yi = y[i]
            gradients = xi.T @ (xi @ theta - yi)
            theta -= lr * gradients
    return time.time() - start

# Fixed number of samples
n_samples = 1000
feature_dims = list(range(100, 2100, 200)) + [2500, 3000, 3500, 4000]

ne_times, sgd_times = [], []

np.random.seed(42)

for n_features in feature_dims:
    X = np.random.randn(n_samples, n_features)
    X = np.c_[np.ones((n_samples, 1)), X]  # Add bias
    y = np.random.randn(n_samples)

    # Normalize features (excluding bias)
    X[:, 1:] = (X[:, 1:] - X[:, 1:].mean(axis=0)) / (X[:, 1:].std(axis=0) + 1e-8)

    ne_times.append(normal_equation_time(X, y))
    sgd_times.append(stochastic_gradient_descent_time(X, y))

# Plot
plt.figure(figsize=(12, 6))
plt.plot(feature_dims, ne_times, 'o-', label='Normal Equation', linewidth=2)
plt.plot(feature_dims, sgd_times, 's-', label='Stochastic Gradient Descent (10 epochs)', linewidth=2)
plt.xlabel('Number of Features')
plt.ylabel('Time (seconds)')
plt.title('Normal Equation vs SGD — Exponential Slowdown of Matrix Inversion')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
# plt.savefig("assets/images/ne_vs_sgd_exponential.png", dpi=150)
plt.show()
