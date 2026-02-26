---
layout: default
title: "Comprehensive Guide to Linear Regression: From Theory to Robust Estimation"
date: 2025-08-05
categories: Machine-learning
tags:
  - ml
  - programming
  - math
---
# Linear Regression: Foundations, Optimization, and Robust Estimation

> **Author**: Mustapha EL BOUAZAOUI <br>
> **Tags**: Machine Learning, Linear Regression, Optimization, RANSAC, Outliers, Gradient Descent, Normal Equation

Linear regression serves as a cornerstone of statistical modeling and supervised machine learning. By establishing a functional relationship between a dependent variable and one or more independent variables, it provides a powerful framework for both prediction and inference. While the concept is conceptually straightforward, a rigorous understanding of its mathematical foundations, optimization techniques, and robust extensions is vital for addressing the complexities of real-world data.

In this article, we provide a comprehensive analysis of the following:
- The **mathematical framework** underlying linear regression.
- The **Normal Equation**: A closed-form solution, its derivation, and its practical limitations.
- A **probabilistic perspective** through Maximum Likelihood Estimation (MLE).
- **Optimization strategies**: Comparing Batch and Stochastic Gradient Descent.
- Addressing **data anomalies**: Robust fitting using the RANSAC (Random Sample Consensus) algorithm.
- Detailed **Python implementations** and comparative visualizations.

---

## 1. Mathematical Foundation of Linear Regression

### Problem Setup

Given a dataset of $ n $ observations:  
$$
\{(x^{(1)}, y^{(1)}), (x^{(2)}, y^{(2)}), \dots, (x^{(n)}, y^{(n)})\}
$$
where $ x^{(i)} \in \mathbb{R}^d $ represents the feature vector and $ y^{(i)} \in \mathbb{R} $ is the target variable, our objective is to learn a linear mapping:

$$
\hat{y} = \theta_0 + \theta_1 x_1 + \theta_2 x_2 + \dots + \theta_d x_d = \theta^T x
$$

To evaluate the model's performance, we employ the **Mean Squared Error (MSE)** cost function:

$$
J(\theta) = \frac{1}{2m} \sum_{i=1}^{m} (\hat{y}^{(i)} - y^{(i)})^2
$$

The goal of the learning process is to identify the parameter vector $ \theta $ that minimizes $ J(\theta) $.

---


## 2. Probabilistic Interpretation: Maximum Likelihood Estimation

Assume the underlying data-generating process follows the form:

$$
y^{(i)} = \theta^T x^{(i)} + \epsilon^{(i)}, \quad \epsilon^{(i)} \sim \mathcal{N}(0, \sigma^2)
$$

In this model, the target $y^{(i)}$ is composed of a deterministic linear component and an additive **Gaussian noise** term. This assumption is frequently justified by the Central Limit Theorem, which suggests that the sum of many independent random errors tends toward a normal distribution.

Under this assumption, the conditional probability of $y^{(i)}$ is given by:

$$
P(y^{(i)} | x^{(i)}; \theta) = \frac{1}{\sqrt{2\pi}\sigma} \exp\left(-\frac{(y^{(i)} - \theta^T x^{(i)})^2}{2\sigma^2}\right)
$$

For an independently and identically distributed (IID) dataset, the **likelihood** function is the product of the individual densities:

$$
\mathcal{L}(\theta) = \prod_{i=1}^{m} P(y^{(i)} | x^{(i)}; \theta)
$$

The **log-likelihood** simplifies this expression for optimization:

$$
\log \mathcal{L}(\theta) = -\frac{m}{2} \log(2\pi) - m \log \sigma - \frac{1}{2\sigma^2} \sum_{i=1}^{m} (y^{(i)} - \theta^T x^{(i)})^2
$$

Maximizing the log-likelihood with respect to $\theta$ is mathematically equivalent to minimizing the sum of squared residuals:

$$
\sum_{i=1}^{m} (y^{(i)} - \theta^T x^{(i)})^2
$$

This derivation provides a rigorous **statistical justification** for the use of Mean Squared Error in linear regression models.

---

## 3. Optimization: Gradient Descent

To minimize the cost function $ J(\theta) $, we typically employ gradient descent, an iterative optimization algorithm:

$$
\theta := \theta - \alpha \nabla_\theta J(\theta)
$$

The method by which we compute the gradient defines the specific variant of the algorithm.

---

### Batch Gradient Descent (BGD)

Batch Gradient Descent utilizes the **entire dataset** to compute the gradient at each iteration.

$$
\nabla_\theta J(\theta) = \frac{1}{m} \sum_{i=1}^{m} (\theta^T x^{(i)} - y^{(i)}) x^{(i)}
$$

**Advantages:**
- Guarantees convergence to the global minimum for convex surfaces.
- Provides a stable and direct path toward the optimal solution.

**Disadvantages:**
- Computationally expensive for very large datasets as the entire matrix must be processed per step.
- Higher memory requirements.

### Stochastic Gradient Descent (SGD)

In contrast, Stochastic Gradient Descent updates the model parameters using **one sample at a time**.

For each observation $ (x^{(i)}, y^{(i)}) $:
$$
\theta := \theta - \alpha (\theta^T x^{(i)} - y^{(i)}) x^{(i)}
$$

**Advantages:**
- Significant reduction in computational cost per iteration.
- The inherent noise in updates can help the model escape shallow local minima in more complex cost surfaces.
- Enables online learning where the model is updated as new data arrives.

**Disadvantages:**
- The parameter trajectory is stochastic (noisy) and may fluctuate around the minimum rather than converging exactly.

---

### Visualization: BGD vs SGD Convergence

The following implementation demonstrates the convergence behavior of both methods on a synthetic dataset.
```python
import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression

# Set random seed for reproducibility
np.random.seed(42)

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
plt.title("Batch Gradient Descent Path")
plt.xlabel("Intercept (θ₀)")
plt.ylabel("Slope (θ₁)")
plt.legend()

plt.subplot(1, 2, 2)
sgd_thetas = theta_sgd_path.squeeze()
plt.plot(sgd_thetas[:, 0], sgd_thetas[:, 1], 'r-o', label='SGD', markersize=2, alpha=0.6)
plt.title("Stochastic Gradient Descent Path")
plt.xlabel("Intercept (θ₀)")
plt.ylabel("Slope (θ₁)")
plt.legend()
plt.tight_layout()
plt.show()
```
![BGD vs SGD Convergence](/assets/images/bgd_vs_sgd.png){: width="80%"}

**Analysis**: BGD follows a smooth, deterministic path toward the minimum, whereas SGD exhibits more erratic behavior. However, SGD's ability to process single samples makes it far more scalable for massive datasets.

---

## 4. The Normal Equation: Closed-Form Solution

While iterative methods are robust, linear regression admits an analytical solution known as the **Normal Equation**.

Given a design matrix $ X \in \mathbb{R}^{m \times n} $ and a target vector $ y \in \mathbb{R}^m $, the optimal parameter vector $ \theta $ can be calculated as:

$$
\theta = (X^T X)^{-1} X^T y
$$

This equation provides the global minimum of the least-squares objective function in a single step.

### Derivation Summary

We aim to minimize the residual sum of squares: $ J(\theta) = \frac{1}{2m}(X\theta - y)^T(X\theta - y) $. Setting the matrix derivative with respect to $\theta$ to zero:

$$
\nabla_\theta J(\theta) = \frac{1}{m} X^T(X\theta - y) = 0
\Rightarrow X^T X \theta = X^T y
\Rightarrow \theta = (X^T X)^{-1} X^T y
$$

### Probabilistic Context

As established in Section 2, the **Maximum Likelihood Estimate (MLE)** under the assumption of independent Gaussian noise is precisely the solution provided by the Normal Equation:

$$
\hat{\theta}_{\text{MLE}} = (X^T X)^{-1} X^T y
$$

This reinforces that the least-squares approach is not merely a heuristic but is statistically optimal when errors are normally distributed.

---

### Limitations of the Normal Equation

Despite its efficiency for small datasets, the Normal Equation has significant computational drawbacks:

| Challenge | Impact |
|------|-------------|
| **Computational Complexity** | Inverting $X^T X$ is $O(n^3)$. This becomes prohibitive as the number of features $n$ grows. |
| **Memory Capacity** | Storing the $n \times n$ matrix $X^T X$ can exceed available RAM for high-dimensional data. |
| **Numerical Instability** | If $X^T X$ is singular (non-invertible due to multicollinearity), the equation fails. |

---

### Feature Scaling and Runtime Performance

We can visualize the performance disparity between the Normal Equation and Gradient Descent as dimensionality increases.
```python 

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

n_samples = 1000
feature_dims = list(range(100, 2100, 200)) + [2500, 3000, 3500, 4000]
ne_times, sgd_times = [], []

np.random.seed(42)

for n_features in feature_dims:
    X = np.random.randn(n_samples, n_features)
    X = np.c_[np.ones((n_samples, 1)), X]
    y = np.random.randn(n_samples)
    X[:, 1:] = (X[:, 1:] - X[:, 1:].mean(axis=0)) / (X[:, 1:].std(axis=0) + 1e-8)

    ne_times.append(normal_equation_time(X, y))
    sgd_times.append(stochastic_gradient_descent_time(X, y))

plt.figure(figsize=(12, 6))
plt.plot(feature_dims, ne_times, 'o-', label='Normal Equation')
plt.plot(feature_dims, sgd_times, 's-', label='SGD (10 epochs)')
plt.xlabel('Number of Features')
plt.ylabel('Time (seconds)')
plt.title('Computation Complexity: Normal Equation vs SGD')
plt.legend()
plt.grid(True, alpha=0.3)
plt.show()
```
![Normal Equation vs Gradient Descent Time](/assets/images/normal_eq_vs_gd_time.png){: width="80%"}

**Observation**: The cubic growth of the Normal Equation's runtime makes it unsuitable for high-dimensional feature spaces where SGD maintains linear scalability.

---

### Numerical Instability with Correlated Features

When features are highly correlated, $ X^T X $ becomes ill-conditioned, leading to unstable solutions.
```python
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
```
![Numerical Instability of Normal Equation](/assets/images/normal_eq_instability.png){: width="80%"}

**Observation**: Tiny changes in data cause large swings in parameters — a sign of **numerical instability** due to multicollinearity.

---

### When to Use the Normal Equation?

| Use Normal Equation When: | Use Gradient Descent Instead When: |
|---------------------------|--------------------------------------|
| $ n < 1000 $ features | $ n > 10,000 $ features |
| You need an **exact solution** | You want **online/iterative** learning |
| Dataset fits in memory | Dataset is too large for $ X^T X $ |
| No multicollinearity | Features are correlated or redundant |

**Note**: `scikit-learn`'s `LinearRegression()` uses **SVD-based solvers** (like `np.linalg.lstsq`) instead of direct inversion to avoid instability.

---
## 5. The Challenge of Outliers

One of the primary weaknesses of Ordinary Least Squares is its lack of robustness to outliers. Because the loss function squares the residuals, observations far from the general trend exert a disproportionate influence on the fitted model.

```python
import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression

X_outlier = np.vstack([X, [0.1], [1.9]])
y_outlier = np.hstack([y, 15, -5])
X_outlier_b = np.c_[np.ones((102, 1)), X_outlier]

theta_clean = np.linalg.inv(X_b.T.dot(X_b)).dot(X_b.T).dot(y)
theta_noisy = np.linalg.inv(X_outlier_b.T.dot(X_outlier_b)).dot(X_outlier_b.T).dot(y_outlier)

X_line = np.linspace(0, 2, 100)
y_clean_line = theta_clean[0] + theta_clean[1] * X_line
y_noisy_line = theta_noisy[0] + theta_noisy[1] * X_line

plt.figure(figsize=(10, 6))
plt.scatter(X, y, color='blue', label='Inliers', alpha=0.7)
plt.scatter([0.1, 1.9], [15, -5], color='red', s=80, label='Outliers')
plt.plot(X_line, y_clean_line, 'g--', label='Fit on Clean Data')
plt.plot(X_line, y_noisy_line, 'r-', label='Fit on Noisy Data')
plt.title('Impact of Outliers on OLS Estimation')
plt.legend()
plt.grid(True, alpha=0.3)
```
![Outliers Drastically Affect Linear Regression](/assets/images/outliers_effect.png){: width="80%"}

Even a small number of severe outliers can significantly tilt the regression line, leading to poor generalization.

---

## 6. RANSAC: Robust Regression via Consensus

To mitigate the influence of outliers, we can use **RANSAC (Random Sample Consensus)**. RANSAC is a non-deterministic algorithm that estimates parameters by consensus among a subset of the data.

### Theoretical Foundation

RANSAC operates on the assumption that the data contains "inliers" (data consistent with a model) and "outliers" (noise or erroneous data).

**The Algorithm:**
1. **Selection**: Randomly select a minimal set of data points (e.g., two for a line).
2. **Estimation**: Fit a model to this minimal subset.
3. **Consensus**: Calculate how many points in the entire dataset fall within a distance threshold $\delta$ of this model. These are the inliers.
4. **Iteration**: Repeat the process for $k$ trials.
5. **Final Model**: Retain the model with the largest consensus (most inliers).

The number of iterations $k$ required to guarantee a successful fit with probability $p$ is:
$$
k = \frac{\log(1 - p)}{\log(1 - w^n)}
$$
where $w$ is the expected fraction of inliers and $n$ is the number of points in the minimal subset.

---

### Implementation with Scikit-Learn

While RANSAC can be implemented from scratch, `scikit-learn` provides a robust and optimized implementation.

```python
import numpy as np

def ransac_linear_regression(X, y, n_samples=2, k_iterations=100, threshold=1.0):
    best_model = None
    best_inliers = None
    max_inliers = 0
    n_points = len(y)
    
    for _ in range(k_iterations):
        # Step 1: Randomly sample minimal set
        idx = np.random.choice(n_points, size=n_samples, replace=False)
        X_sample = X[idx].reshape(-1, 1)
        y_sample = y[idx]
        
        # Step 2: Fit model using Normal Equation
        X_sample_b = np.c_[np.ones(X_sample.shape[0]), X_sample]
        try:
            model = np.linalg.solve(X_sample_b.T @ X_sample_b, X_sample_b.T @ y_sample)
        except np.linalg.LinAlgError:
            continue  # Skip if singular
        
        # Step 3: Predict and find inliers
        y_pred = model[0] + model[1] * X
        inliers = np.abs(y - y_pred) < threshold
        
        num_inliers = np.sum(inliers)
        if num_inliers > max_inliers:
            max_inliers = num_inliers
            best_model = model
            best_inliers = inliers
    
    return best_model, best_inliers

# Example usage
# model, inliers = ransac_linear_regression(X_data, y_data, threshold=2.0)
```

**RANSAC (Random Sample Consensus)** is an iterative algorithm that estimates parameters by fitting models to **random subsets** of data and selecting the one with the most inliers.

### using scikit-learn (good for production)
```python
from sklearn.linear_model import RANSACRegressor, LinearRegression

# Define RANSAC with custom settings
ransac = RANSACRegressor(
    estimator=LinearRegression(),
    min_samples=2,                # Minimal points to fit (2 for line)
    residual_threshold=2.0,       # Max residual to be inlier
    max_trials=100,               # Max iterations
    stop_n_inliers=len(X)//2,     # Stop if half are inliers
    random_state=42
)

# Fit model
ransac.fit(X.reshape(-1, 1), y)

# Get inlier mask
inlier_mask = ransac.inlier_mask_
outlier_mask = ~inlier_mask

# Predict
y_ransac = ransac.predict(X.reshape(-1, 1))
```

### Advantages of RANSAC:
- Highly robust to noise and extreme outliers.
- Effective even when outliers constitute a significant portion (up to 50%) of the dataset.

---

### RANSAC Visualization


![RANSAC: Inliers vs Outliers and Model Comparison](/assets/images/ransac_vs_ols.png){: width="80%"}

**Insight**: RANSAC successfully ignores outliers and recovers a line close to the true underlying model.

---

## 7. Comparative Summary

| Method | Best Use Case | Key Limitation |
|-------|---------|---------|
| **Normal Equation** | Small datasets with few features | Scales poorly with dimensionality ($O(n^3)$) |
| **Batch GD** | Small to medium datasets | Can be slow on very large data |
| **Stochastic GD** | Large scale or streaming data | Trajectory is noisy; approximate convergence |
| **RANSAC** | Datasets with high outlier contamination | Increased computational overhead per trial |

---

## 8. Conclusion

Linear regression remains a foundational tool in the data scientist's arsenal. By moving beyond simple line-fitting and understanding the **probabilistic underpinnings**, **optimization trade-offs**, and **robustness techniques**, one can build models that are both accurate across clean data and resilient in the presence of noise.

Key Takeaways:
- **Optimization**: Choose between exact solutions (Normal Equation) and scalable approximations (SGD) based on data volume.
- **Robustness**: Always assess data for outliers and consider consensus-based methods like RANSAC when necessary.
- **Statistical Fidelity**: Recall that minimizing MSE is equivalent to maximum likelihood estimation under Gaussian assumptions.

---

## Code and Resources

Additional implementation details and figure generation scripts can be found here:
- Full Python implementation: [linear_regression_analysis.py](https://github.com/Ahpatsum15/Ahpatsum15.github.io/blob/main/assets/linear_regression.py)
- Visualization assets: `assets/images/`

---

## References

- Bishop, C. M. (2006). *Pattern Recognition and Machine Learning*. Springer.
- Goodfellow, I., Bengio, Y., & Courville, A. (2016). *Deep Learning*. MIT Press.
- Scikit-learn Documentation: [Robust Regression Models](https://scikit-learn.org/stable/modules/linear_model.html#robust-regression-outliers-and-modeling-errors).
- Andrew Ng’s Machine Learning Course CSS229