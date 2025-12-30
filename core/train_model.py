import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
import os

class SAFSTrainer:
    """
    V-APF AI 训练引擎
    功能：
    1. 加载标注好的数据集 (data/train_dataset.csv)
    2. 执行特征工程 (Log Scaling, Z-score Normalization)
    3. 训练 Random Forest 分类器 (处理类别不平衡)
    4. 评估模型并保存 (.pkl)
    """
    def __init__(self, csv_path):
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"数据集未找到: {csv_path}")
        self.df = pd.read_csv(csv_path)
        self.model = None
        self.scaler = StandardScaler()

    def preprocess(self):
        # 1. 提取特征 (v1-v13) 和 标签
        # 确保列名匹配
        feature_cols = [f'v{i}' for i in range(1, 14)]
        X = self.df[feature_cols].values
        y = self.df['label'].values

        # 2. 特征工程：Log 缩放 (针对 v1 长度和 v3 时间，防止极端值干扰)
        # v1: Length Diff Ratio (可以是负数，先取绝对值) -> log1p
        # v3: Time Delay (秒) -> log1p
        # 注意：v1 和 v3 是第 0 和 第 2 列
        X[:, 0] = np.log1p(np.abs(X[:, 0])) 
        X[:, 2] = np.log1p(np.abs(X[:, 2]))

        # 3. 标准化归一化 (Z-score)
        # 这对于随机森林不是必须的，但对于后续可能接入的神经网络或 SVM 非常重要
        # 且有助于统一特征量纲
        X = self.scaler.fit_transform(X)
        
        return X, y

    def train(self):
        print("[*] 正在准备特征工程...")
        X, y = self.preprocess()

        # 划分训练集和测试集 (由于正样本太少，使用 stratify 保证比例一致)
        # 80% 训练，20% 测试
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        print(f"[*] 训练集规模: {len(X_train)} (正样本: {sum(y_train)})")
        print(f"[*] 测试集规模: {len(X_test)} (正样本: {sum(y_test)})")
        
        # 随机森林模型配置
        # 显式偏向负类，降低过拟合深度，并要求叶子最少样本，期望降低 FP
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_leaf=2,
            class_weight={0: 1.3, 1: 1.7},
            random_state=42,
            n_jobs=-1 # 并行训练
        )

        print("[*] AI 引擎训练中...")
        self.model.fit(X_train, y_train)

        # 评估结果 (使用默认阈值 0.5)
        y_pred = self.model.predict(X_test)
        print("\n=== 模型评估报告 (Threshold=0.5) ===")
        print(classification_report(y_test, y_pred, zero_division=0))
        print("混淆矩阵:")
        print(confusion_matrix(y_test, y_pred))
        
        # [Optimization] 阈值调优分析 (Threshold Tuning)
        # 我们更关注 Recall (漏报越少越好)，因此尝试降低阈值
        y_probs = self.model.predict_proba(X_test)[:, 1] # 获取正样本概率
        
        print("\n=== 阈值调优分析 ===")
        thresholds = [0.2, 0.3, 0.4, 0.5, 0.55, 0.6, 0.65, 0.7]
        for t in thresholds:
            y_pred_t = (y_probs >= t).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_test, y_pred_t).ravel()
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            print(f"Threshold {t:.2f}: Recall={recall:.4f}, Precision={precision:.4f} (FP={fp})")
        
        # 特征重要性分析
        feature_names = [f'v{i}' for i in range(1, 14)]
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        print("\n=== 特征重要性排名 ===")
        for f in range(X_train.shape[1]):
            print(f"{f+1}. {feature_names[indices[f]]}: {importances[indices[f]]:.4f}")

    def save(self, model_path="models/safs_rf_model.pkl", scaler_path="models/scaler.pkl"):
        os.makedirs("models", exist_ok=True)
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        print(f"\n[+] 模型已产出: {model_path}")
        print(f"[+] 预处理器已产出: {scaler_path}")

if __name__ == "__main__":
    trainer = SAFSTrainer("data/train_dataset.csv")
    trainer.train()
    trainer.save()
