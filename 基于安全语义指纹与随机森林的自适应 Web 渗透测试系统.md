# **基于安全语义指纹与随机森林的自适应 Web 渗透测试系统 (SAFS-Scanner)**

**Adaptive Web Penetration Testing Framework based on Security Semantic Fingerprinting and Random Forest**

------

## 一、 项目综述

### 1.1 系统定位

本系统是一款基于**机器学习驱动**的自动化 Web 安全检测框架。区别于传统的依赖正则匹配或硬编码规则的扫描器，本系统通过采集 Web 页面在受到攻击扰动前后的**语义指纹差异**，利用**随机森林 (Random Forest)** 分类算法实现对 SQL 注入 (SQLi)、跨站脚本 (XSS) 及本地文件包含 (LFI) 等主流漏洞的自适应识别。

### 1.2 核心特性

- **语义指纹化**：将复杂的 HTTP 报文高度压缩为 13 维安全语义特征向量。
- **环境自适应**：引入基准指纹 (Baseline) 对比机制，消除不同 Web 架构对检测结果的干扰。
- **启发式打标**：结合安全等级策略与特征反馈循环，自动化生成高纯净度训练数据集。
- **高稳健性**：采用分层采样交叉验证 (Stratified K-Fold)，确保模型在小样本集下仍具备极强的泛化能力。

------

## 二、 系统架构与模块设计

### 2.1 模块分工

| **模块名称**         | **核心文件**         | **逻辑功能**                                                 |
| -------------------- | -------------------- | ------------------------------------------------------------ |
| **全等级指纹爬虫**   | `spider.py`          | 执行深度优先爬取，处理自动化登录态，针对不同安全防御等级生成对比样本。 |
| **语义特征提取器**   | `extractor.py`       | 执行 Fuzzing 探测。对比 Base 请求与 Probe 请求，提取 13 维稠密特征向量。 |
| **动态启发式打标机** | `auto_labeler.py`    | 依据安全等级背景与 Fuzzing 反馈特征，通过启发式算法自动标注样本标签。 |
| **随机森林 AI 引擎** | `train_model.py`     | 执行特征工程（Log 缩放、归一化）与模型训练，产出高维分类决策模型。 |
| **自动化预测扫描器** | `predict_scanner.py` | 实时加载模型，对未知端点执行动态探测并给出漏洞概率评分 $P$。 |

------

## 三、 特征工程 (Feature Engineering)

系统将每一个探测动作抽象为一个 $1 \times 13$ 的特征向量，旨在通过最小维度的信息捕获最大的安全语义变化。

### 3.1 核心特征维度定义

1. **反射特征 (`probe_reflected`)**：Payload 关键词是否在响应体中原样回显（XSS 核心指标）。
2. **结构差异对数 (`len_diff_log`)**：使用 $\ln(\Delta \text{Length} + 1)$ 计算响应长度变化，降低长页面扰动权重。
3. **DOM 树变动 (`has_text_diff`)**：判定 HTML 标签结构是否发生非预期的层级坍塌。
4. **语义报错特征 (`has_sql_error_probe`)**：检测响应中是否包含数据库特有的异常堆栈信息。
5. **上下文定位指纹 (`log_base_len`)**：记录页面原始长度对数，辅助模型识别当前的业务模块上下文。
6. **时序延迟特征 (`resp_time_diff`)**：计算探测请求与基准请求的耗时差，识别时间型盲注漏洞。

------

## 四、 关键工作流 (Workflow)

### 4.1 数据准备阶段 (Data Preparation)

1. **多源采集**：从 DVWA、bWAPP、Mutillidae 等多类靶场采集原始流量。
2. **特征对齐**：统一所有采集来源的特征格式，执行归一化处理。
3. **归一化公式**：对连续数值特征执行 $x' = \frac{x - \mu}{\sigma}$ 或 Log 缩放，确保模型收敛。

### 4.2 模型训练阶段 (Model Training)

系统采用带网格搜索 (GridSearch) 的随机森林算法：

- **评估指标**：优先观测 F1-Score 与 Stratified CV Mean。

- **过拟合抑制**：限制决策树最大深度 $max\_depth$，设置叶子节点最小样本数 $min\_samples\_leaf$。

- **执行命令**：

  Bash

  ```
  python train_model.py --in data/all_merged.csv --model models/safs_v1.pkl
  ```

### 4.3 自动化扫描阶段 (Inference)

1. **基准采样**：获取目标 URL 的 `base_fingerprint`。

2. **变异注入**：发送针对性的变异 Payload。

3. **向量生成**：实时计算探测点的 13 维特征。

4. 概率判定：

   

   $$Result = \begin{cases} \text{Vulnerable}, & P(label=1) > 0.8 \\ \text{Suspicious}, & 0.5 < P(label=1) \le 0.8 \\ \text{Safe}, & P(label=1) \le 0.5 \end{cases}$$

------

## 五、 性能评估指标 (Evaluation)

系统的有效性通过以下维度衡量：

- **漏报率 (False Negative Rate)**：通过全等级爬虫构建的 Impossible 等级样本，检验模型对防御状态的识别准确度。
- **泛化能力**：在 A 靶场训练的模型，直接在 B 靶场进行未标记扫描的准确率。
- **稳定性**：5 折分层交叉验证的方差均值，要求 $Var(CV) < 0.05$。