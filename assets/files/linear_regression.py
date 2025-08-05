# linear_regression_blog.py
# Generates all plots for the blog post

import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression

# Set random seed
np.random.seed(42)

# ========================================
# 1. BGD vs SGD Convergence
# ========================================
X = 2 * np.random.rand(100, 1)
y = 4 + 3 * X.squeeze() + np.random.randn(100)
X_b = np.c_[np.ones((100, 1)), X]

def batch_gradient_descent(X, y, lr=0.1, n_iters=20):
    theta = np.random.randn(2, 1)
    theta_path = []
    m = len(y)
    for i in range(n_iters):
        gradients = (1/m) * X.T.dot(X.dot(theta) - y.reshape(-1,1))
        theta = theta - lr * gradients
        theta_path.append(theta.copy())
    return np.array(theta_path)

def stochastic_gradient_descent(X, y, lr=0.1, n_epochs=2):
    theta = np.random.randn(2, 1)
    theta_path = []
    m = len(y)
    for epoch in range(n_epochs):
        for i in range(m):
            xi = X[i:i+1]
            yi = y[i:i+1].reshape(-1,1)
            gradients = xi.T.dot(xi.dot(theta) - yi)
            theta = theta - lr * gradients
            theta_path.append(theta.copy())
    return np.array(theta_path)

theta_bgd_path = batch_gradient_descent(X_b, y)
theta_sgd_path = stochastic_gradient_descent(X_b, y)

plt.figure(figsize=(12, 6))
plt.subplot(1, 2, 1)
bgd_thetas = theta_bgd_path.squeeze()
plt.plot(bgd_thetas[:, 0], bgd_thetas[:, 1], 'b-s', label='BGD', markersize=4)
plt.title("Batch Gradient Descent")
plt.xlabel("Intercept (θ₀)")
plt.ylabel("Slope (θ₁)")
plt.legend()

plt.subplot(1, 2, 2)
sgd_thetas = theta_sgd_path.squeeze()
plt.plot(sgd_thetas[:, 0], sgd_thetas[:, 1], 'r-o', label='SGD', markersize=2, alpha=0.6)
plt.title("Stochastic Gradient Descent")
plt.xlabel("Intercept (θ₀)")
plt.ylabel("Slope (θ₁)")
plt.legend()
plt.tight_layout()
plt.savefig(r"C:\Users\musta\OneDrive\Bureau\Ahpatsum15.github.io\assets\images\bgd_vs_sgd.png", dpi=150)
plt.close()

# ========================================
# 2. Outliers Effect
# ========================================
X_outlier = np.vstack([X, [0.1], [1.9]])
y_outlier = np.hstack([y, 15, -5])
X_outlier_b = np.c_[np.ones((102, 1)), X_outlier]

theta_clean = np.linalg.inv(X_b.T.dot(X_b)).dot(X_b.T).dot(y)
theta_noisy = np.linalg.inv(X_outlier_b.T.dot(X_outlier_b)).dot(X_outlier_b.T).dot(y_outlier)

X_line = np.linspace(0, 2, 100)
y_clean_line = theta_clean[0] + theta_clean[1] * X_line
y_noisy_line = theta_noisy[0] + theta_noisy[1] * X_line

plt.figure(figsize=(10, 6))
plt.scatter(X, y, color='blue', label='Clean data', alpha=0.7)
plt.scatter([0.1, 1.9], [15, -5], color='red', s=80, label='Outliers', zorder=5)
plt.plot(X_line, y_clean_line, 'g--', label=f'Clean Fit: y = {theta_clean[0]:.2f} + {theta_clean[1]:.2f}x')
plt.plot(X_line, y_noisy_line, 'r-', label=f'Noisy Fit: y = {theta_noisy[0]:.2f} + {theta_noisy[1]:.2f}x')
plt.xlabel('X')
plt.ylabel('y')
plt.title('Outliers Drastically Affect Linear Regression')
plt.legend()
plt.grid(True, alpha=0.3)
plt.savefig(r"C:\Users\musta\OneDrive\Bureau\Ahpatsum15.github.io\assets\images\outliers_effect.png", dpi=150)
plt.close()

# ========================================
# 3. RANSAC vs OLS
# ========================================
def ransac_linear_regression(X, y, n_samples=2, k_iterations=100, threshold=1.0, inlier_ratio=0.6):
    best_model = None
    best_inliers = None
    max_inliers = 0
    n_points = len(y)

    for i in range(k_iterations):
        idx = np.random.choice(n_points, size=n_samples, replace=False)
        X_sample = X[idx].reshape(-1, 1)
        y_sample = y[idx]

        model = LinearRegression()
        model.fit(X_sample, y_sample)

        y_pred = model.predict(X.reshape(-1, 1))
        inliers = np.abs(y - y_pred) < threshold

        num_inliers = np.sum(inliers)
        if num_inliers > max_inliers:
            max_inliers = num_inliers
            best_model = model
            best_inliers = inliers

        if num_inliers >= int(inlier_ratio * n_points):
            break

    return best_model, best_inliers

model_ransac, inliers = ransac_linear_regression(X_outlier, y_outlier, threshold=2.0)
X_in = X_outlier[inliers].reshape(-1, 1)
y_in = y_outlier[inliers]
final_model = LinearRegression().fit(X_in, y_in)
y_ransac = final_model.predict(X_line.reshape(-1, 1))

plt.figure(figsize=(12, 6))
plt.subplot(1, 2, 1)
plt.scatter(X_outlier[~inliers], y_outlier[~inliers], color='red', s=60, label='Outliers', zorder=5)
plt.scatter(X_outlier[inliers], y_outlier[inliers], color='blue', s=30, label='Inliers', alpha=0.7)
plt.plot(X_line, y_ransac, 'green', linewidth=2, label='RANSAC Fit')
plt.title('RANSAC: Inliers vs Outliers')
plt.xlabel('X')
plt.ylabel('y')
plt.legend()
plt.grid(True, alpha=0.3)

plt.subplot(1, 2, 2)
plt.scatter(X_outlier, y_outlier, color='gray', alpha=0.6, label='Data (with outliers)')
plt.plot(X_line, y_clean_line, 'g--', label='Clean OLS')
plt.plot(X_line, y_noisy_line, 'r-', label='OLS with Outliers')
plt.plot(X_line, y_ransac, 'k-', linewidth=2, label='RANSAC Fit')
plt.xlabel('X')
plt.ylabel('y')
plt.title('Model Comparison')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(r"C:\Users\musta\OneDrive\Bureau\Ahpatsum15.github.io\assets\images\ransac_vs_ols.png", dpi=150)
plt.close()



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
plt.savefig("assets/images/ne_vs_sgd_exponential.png", dpi=150)
plt.show()
plt.close()

#---
import numpy as np
import matplotlib.pyplot as plt

# Generate correlated features
np.random.seed(42)
n_samples = 50

x1 = np.random.randn(n_samples)
x2 = x1 + 0.01 * np.random.randn(n_samples)  # Highly correlated with x1

X_corr = np.c_[np.ones(n_samples), x1, x2]
y = 3 * x1 + 2 + np.random.randn(n_samples) * 0.5

# Compute theta using np.linalg.lstsq (more stable)
theta_exact, residuals, rank, s = np.linalg.lstsq(X_corr, y, rcond=None)

# Perturb X and recompute theta
X_perturbed = X_corr + 0.001 * np.random.randn(*X_corr.shape)
theta_perturbed, _, _, _ = np.linalg.lstsq(X_perturbed, y, rcond=None)

# Print results
print("Exact solution:", np.round(theta_exact, 3))
print("Perturbed solution:", np.round(theta_perturbed, 3))
print("Difference norm:", np.linalg.norm(theta_exact - theta_perturbed))

# Plot
labels = ['θ₀ (bias)', 'θ₁ (x₁)', 'θ₂ (x₂)']
x = np.arange(len(labels))
width = 0.35

plt.figure(figsize=(10, 6))
bars1 = plt.bar(x - width/2, theta_exact, width, label='Original Data', color='skyblue')
bars2 = plt.bar(x + width/2, theta_perturbed, width, label='Perturbed Data', color='salmon')

plt.axhline(0, color='gray', linewidth=0.8, linestyle='--')

plt.xlabel('Parameter')
plt.ylabel('Coefficient Value')
plt.title('Normal Equation Sensitivity: Correlated Features & Small Noise')
plt.xticks(x, labels)
plt.legend()
plt.grid(True, axis='y', alpha=0.3)

# Annotate bars with their heights
def annotate_bars(bars):
    for bar in bars:
        height = bar.get_height()
        plt.annotate(f'{height:.2f}',
                     xy=(bar.get_x() + bar.get_width() / 2, height),
                     xytext=(0, 5),  # 5 points vertical offset
                     textcoords="offset points",
                     ha='center', va='bottom',
                     fontsize=9)

annotate_bars(bars1)
annotate_bars(bars2)

plt.tight_layout()
plt.show()

plt.savefig(r"C:\Users\musta\OneDrive\Bureau\Ahpatsum15.github.io\assets\images\normal_eq_instability.png", dpi=150)
plt.close()

print("✅ All images generated in 'images/' folder!")