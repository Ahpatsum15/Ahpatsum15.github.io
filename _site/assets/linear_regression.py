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
plt.savefig("/images/bgd_vs_sgd.png", dpi=150)
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
plt.savefig("/images/outliers_effect.png", dpi=150)
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
plt.savefig("/images/ransac_vs_ols.png", dpi=150)
plt.close()




import time

def normal_equation_time(X, y):
    start = time.time()
    try:
        theta = np.linalg.inv(X.T @ X) @ X.T @ y
    except np.linalg.LinAlgError:
        theta = None
    end = time.time()
    return end - start

def gradient_descent_time(X, y, lr=0.01, n_iters=1000):
    start = time.time()
    theta = np.random.randn(X.shape[1])
    m = len(y)
    for i in range(n_iters):
        gradients = (1/m) * X.T @ (X @ theta - y)
        theta = theta - lr * gradients
    end = time.time()
    return end - start

# Vary number of features
n_samples = 100
feature_dims = np.arange(10, 201, 20)
ne_times = []
gd_times = []

np.random.seed(42)

for n_features in feature_dims:
    X = np.random.randn(n_samples, n_features)
    X = np.c_[np.ones((n_samples, 1)), X]  # add bias
    y = np.random.randn(n_samples)

    # Normalize for GD stability
    X[:, 1:] = (X[:, 1:] - X[:, 1:].mean(axis=0)) / X[:, 1:].std(axis=0)

    t_ne = normal_equation_time(X, y)
    t_gd = gradient_descent_time(X, y)

    ne_times.append(t_ne)
    gd_times.append(t_gd)

# Plot
plt.figure(figsize=(10, 6))
plt.plot(feature_dims, ne_times, 'o-', label='Normal Equation', linewidth=2)
plt.plot(feature_dims, gd_times, 's-', label='Gradient Descent', linewidth=2)
plt.xlabel('Number of Features (n)')
plt.ylabel('Computation Time (seconds)')
plt.title('Normal Equation vs Gradient Descent Scaling')
plt.legend()
plt.grid(True, alpha=0.3)
plt.savefig("/images/normal_eq_vs_gd_time.png", dpi=150)
plt.show()
plt.close()

# Generate correlated features
np.random.seed(42)
n_samples = 50

# Feature 1: random
x1 = np.random.randn(n_samples)

# Feature 2: almost identical to x1 (high correlation)
x2 = x1 + 0.01 * np.random.randn(n_samples)  # x2 ≈ x1

X_corr = np.c_[np.ones(n_samples), x1, x2]
y = 3 * x1 + 2 + np.random.randn(n_samples) * 0.5

# Solve using Normal Equation
try:
    theta_exact = np.linalg.inv(X_corr.T @ X_corr) @ X_corr.T @ y
except np.linalg.LinAlgError:
    theta_exact = np.nan * np.ones(3)

# Solve using SVD (more stable — what sklearn uses)
theta_svd = np.linalg.solve(X_corr.T @ X_corr, X_corr.T @ y)  # or use np.linalg.lstsq

# Perturb data slightly and recompute
X_perturbed = X_corr + 0.001 * np.random.randn(*X_corr.shape)
try:
    theta_perturbed = np.linalg.inv(X_perturbed.T @ X_perturbed) @ X_perturbed.T @ y
except:
    theta_perturbed = np.nan * np.ones(3)

# Compare
print("Exact solution:", np.round(theta_exact, 3))
print("Perturbed solution:", np.round(theta_perturbed, 3))
print("Difference:", np.linalg.norm(theta_exact - theta_perturbed))

# Plot sensitivity
labels = ['θ₀ (bias)', 'θ₁ (x₁)', 'θ₂ (x₂)']
x = np.arange(3)
width = 0.35

plt.figure(figsize=(10, 6))
plt.bar(x - width/2, theta_exact, width, label='Original Data', color='skyblue')
plt.bar(x + width/2, theta_perturbed, width, label='Perturbed Data', color='salmon')

plt.xlabel('Parameter')
plt.ylabel('Value')
plt.title('Normal Equation: High Sensitivity to Noise (Correlated Features)')
plt.xticks(x, labels)
plt.legend()
plt.grid(True, axis='y', alpha=0.3)
plt.savefig("/images/normal_eq_instability.png", dpi=150)
plt.show()
plt.close()

print("✅ All images generated in 'images/' folder!")