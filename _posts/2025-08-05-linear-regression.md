---
layout: default
title: Linear Regression & beyond
date: 2025-08-05
categories: Machine-learning
tags:
  - ml
  - programming
  - math
---
# 📊 Linear Regression: Mathematical Foundations, Gradient Descent, and Robust Fitting with RANSAC

> **Author**: Mustapha EL BOUAZAOUI <br>
> **Tags**: Machine Learning, Linear Regression, Optimization, RANSAC, Outliers, Gradient Descent, Normal Equation

Linear regression is one of the most fundamental tools in machine learning and statistics. It models the relationship between a dependent variable and one or more independent variables using a linear equation. While it's simple, its mathematical foundation, optimization methods, and robust variants are essential for real-world applications.

In this blog, we'll explore:
- The **mathematical foundation** of linear regression
- The **Normal Equation** — closed-form solution and its limitations
- **Probability interpretation** via Maximum Likelihood
- **Batch vs. Stochastic Gradient Descent** — differences and when to use each
- Handling **outliers** with **RANSAC (Random Sample Consensus)**
- Full **Python implementations** with visualizations

Let’s dive in!

---

## 1. 📘 Mathematical Foundation of Linear Regression

### Problem Setup

Given a dataset of $ n $ samples:  
$$
\{(x^{(1)}, y^{(1)}), (x^{(2)}, y^{(2)}), \dots, (x^{(n)}, y^{(n)})\}
$$
where $ x^{(i)} \in \mathbb{R}^d $ and $ y^{(i)} \in \mathbb{R} $, we want to find a linear model:

$$
\hat{y} = \theta_0 + \theta_1 x_1 + \theta_2 x_2 + \dots + \theta_d x_d = \theta^T x
$$

We define the **Mean Squared Error (MSE)** cost function:

$$
J(\theta) = \frac{1}{2m} \sum_{i=1}^{m} (\hat{y}^{(i)} - y^{(i)})^2
$$

Our goal is to minimize $ J(\theta) $.

---

## 2. 📘 The Normal Equation: Closed-Form Solution

While gradient descent iteratively minimizes the cost function, there's an alternative: the **Normal Equation** — a **closed-form solution** to linear regression.

Given the design matrix $ X \in \mathbb{R}^{m \times n} $ (with $ m $ samples and $ n $ features, including bias), and target vector $ y \in \mathbb{R}^m $, the optimal parameter vector $ \theta $ is:

$$
\theta = (X^T X)^{-1} X^T y
$$

This directly gives the **exact solution** to the least-squares problem without iteration.

### ✅ Derivation (Brief)

We minimize $ J(\theta) = \frac{1}{2m}(X\theta - y)^T(X\theta - y) $

Take gradient w.r.t $ \theta $ and set to zero:

$$
\nabla_\theta J(\theta) = \frac{1}{m} X^T(X\theta - y) = 0
\Rightarrow X^T X \theta = X^T y
\Rightarrow \theta = (X^T X)^{-1} X^T y
$$

---

### 🔍 Probability Interpretation

Assume the true relationship is:

$$
y^{(i)} = \theta^T x^{(i)} + \epsilon^{(i)}
$$

where $ \epsilon^{(i)} \sim \mathcal{N}(0, \sigma^2) $ is Gaussian noise.

Then the **Maximum Likelihood Estimate (MLE)** of $ \theta $ is:

$$
\hat{\theta}_{\text{MLE}} = (X^T X)^{-1} X^T y
$$

So, the **Normal Equation solution = MLE under Gaussian noise**.

This reinforces that least squares isn't just arbitrary — it's statistically **optimal** when errors are normal and independent.

---

### ⚠️ Limitations of the Normal Equation

Despite its elegance, the Normal Equation has **three major limitations**:

| Issue | Explanation |
|------|-------------|
| **Computational Cost** | $ O(n^3) $ due to matrix inversion — slow for large $ n $ (e.g., 10k+ features) |
| **Memory Usage** | Must store $ X^T X \in \mathbb{R}^{n \times n} $ — infeasible for huge $ n $ |
| **Singular $ X^T X $** | Fails if $ X^T X $ is non-invertible (e.g., redundant features, $ m < n $) |

Let’s visualize these issues.

---

### 📉 Illustration 1: Computation Time vs Number of Features

We compare **Normal Equation** vs **Gradient Descent** runtime as the number of features increases.

![Normal Equation vs Gradient Descent Time](/assets/images/normal_eq_vs_gd_time.png){: width="80%"}

> **Observation**: Normal Equation time grows rapidly — **cubic in $ n $** — while GD scales linearly per iteration.

---

### 📉 Illustration 2: Numerical Instability with Correlated Features

When features are highly correlated, $ X^T X $ becomes ill-conditioned, leading to unstable solutions.

![Numerical Instability of Normal Equation](/assets/images/normal_eq_instability.png){: width="80%"}

> **Observation**: Tiny changes in data cause large swings in parameters — sign of **numerical instability** due to multicollinearity.

---

### ✅ When to Use the Normal Equation?

| Use Normal Equation When: | Use Gradient Descent Instead When: |
|---------------------------|--------------------------------------|
| $ n < 1000 $ features | $ n > 10,000 $ features |
| You need **exact solution** | You want **online/iterative** learning |
| Dataset fits in memory | Dataset is too large for $ X^T X $ |
| No multicollinearity | Features are correlated or redundant |

💡 **Fun Fact**: `scikit-learn`'s `LinearRegression()` uses **SVD-based solvers** (like `np.linalg.lstsq`) instead of direct inversion to avoid instability.

---

## 3. 🔮 Probability Interpretation: Maximum Likelihood

Assume the true relationship is:

$$
y^{(i)} = \theta^T x^{(i)} + \epsilon^{(i)}
$$

where $ \epsilon^{(i)} \sim \mathcal{N}(0, \sigma^2) $ is Gaussian noise.

Then the probability of observing $ y^{(i)} $ is:

$$
P(y^{(i)} | x^{(i)}; \theta) = \frac{1}{\sqrt{2\pi}\sigma} \exp\left(-\frac{(y^{(i)} - \theta^T x^{(i)})^2}{2\sigma^2}\right)
$$

The likelihood over all samples:

$$
\mathcal{L}(\theta) = \prod_{i=1}^{m} P(y^{(i)} | x^{(i)}; \theta)
$$

Taking log-likelihood:

$$
\log \mathcal{L}(\theta) = \text{const} - \frac{1}{2\sigma^2} \sum_{i=1}^{m} (y^{(i)} - \theta^T x^{(i)})^2
$$

Maximizing log-likelihood is equivalent to minimizing MSE. Hence, **least squares = maximum likelihood under Gaussian noise**.

---

## 4. ⚙️ Optimization: Gradient Descent

To minimize $ J(\theta) $, we use gradient descent:

$$
\theta := \theta - \alpha \nabla_\theta J(\theta)
$$

But how we compute the gradient leads to two main variants.

---

### 🔁 Batch Gradient Descent (BGD)

Uses the **entire dataset** to compute the gradient at each step.

$$
\nabla_\theta J(\theta) = \frac{1}{m} \sum_{i=1}^{m} (\theta^T x^{(i)} - y^{(i)}) x^{(i)}
$$

✅ **Pros**:
- Stable convergence  
- Smooth path to minimum

❌ **Cons**:
- Slow for large datasets  
- Memory-intensive

### 🏃 Stochastic Gradient Descent (SGD)

Updates parameters using **one sample at a time**.

For each $ (x^{(i)}, y^{(i)}) $:
$$
\theta := \theta - \alpha (\theta^T x^{(i)} - y^{(i)}) x^{(i)}
$$

✅ **Pros**:
- Fast per-iteration updates  
- Can escape shallow local minima  
- Online learning possible

❌ **Cons**:
- Noisy updates  
- May not converge exactly to minimum

---

### 📈 Visualization: BGD vs SGD Convergence

Let's generate a simple 1D regression and plot the convergence paths.

![BGD vs SGD Convergence](/assets/images/bgd_vs_sgd.png){: width="80%"}

> **Interpretation**: BGD takes a smooth path toward the minimum. SGD jumps around but trends toward it. SGD is faster per step but noisier.

---

## 5. 🚨 The Problem of Outliers

Outliers can severely distort linear regression models. Let's see how.

![Outliers Drastically Affect Linear Regression](/assets/images/outliers_effect.png){: width="80%"}

> **Observation**: The two red points pull the regression line significantly, making it a poor fit for the majority of data.

---

## 6. 🛠️ RANSAC: Robust Regression

**RANSAC (Random Sample Consensus)** is an iterative algorithm that estimates parameters by fitting models to **random subsets** of data and selecting the one with the most inliers.

### How RANSAC Works:

1. Randomly select a minimal subset (e.g., 2 points for line fitting).
2. Fit a model to this subset.
3. Count how many points are **inliers** (within a threshold distance).
4. Repeat for a number of iterations.
5. Return the model with the most inliers.

### Advantages:
- Robust to outliers
- Works well when >50% of data are inliers

---

### ✅ RANSAC Implementation and Visualization

![RANSAC: Inliers vs Outliers and Model Comparison](/assets/images/ransac_vs_ols.png){: width="80%"}

> **Insight**: RANSAC successfully ignores outliers and recovers a line close to the true underlying model.

---

## 7. 🧠 When to Use Which?

| Method | Use Case |
|-------|---------|
| **Normal Equation** | Small datasets ($n < 1000$), exact solution needed |
| **Batch GD** | Small to medium datasets, stable convergence |
| **Stochastic GD** | Large datasets, online learning, fast initial progress |
| **OLS (Normal Eq)** | Small to medium datasets, no outliers |
| **RANSAC** | Presence of significant outliers, robust fitting needed |

---

## 8. 🔚 Conclusion

Linear regression is more than just fitting a line. Understanding its **probabilistic basis**, **optimization strategies**, and **robust variants** like RANSAC allows us to build models that are not only accurate but also reliable in the face of noise and outliers.

Key takeaways:
- The **Normal Equation** gives the exact solution but scales poorly.
- **BGD** is precise but slow; **SGD** is fast but noisy.
- **Outliers** can ruin OLS — always visualize and clean data.
- **RANSAC** is a powerful tool for robust regression in real-world settings.

---

## 📁 Code & Figures

All code and generated images:
- `normal_eq_vs_gd_time.png`
- `normal_eq_instability.png`
- `bgd_vs_sgd.png`
- `outliers_effect.png`
- `ransac_vs_ols.png`
- Full Python script: [linear_regression_blog.py](https://github.com/Ahpatsum15/Ahpatsum15.github.io/blob/main/assets/linear_regression.py)

> 💡 **Tip**: You can extend RANSAC to polynomial regression, plane fitting in 3D, or even homography estimation in computer vision!

---

## 🙌 References

- Bishop, C. M. (2006). *Pattern Recognition and Machine Learning*
- Goodfellow, I., Bengio, Y., & Courville, A. (2016). *Deep Learning*
- Scikit-learn Documentation: [RANSACRegressor](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.RANSACRegressor.html)
- Andrew Ng’s Machine Learning Course CSS229 