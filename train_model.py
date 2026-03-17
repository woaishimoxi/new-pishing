#!/usr/bin/env python3
"""
模型训练脚本
使用 example 项目的数据集训练 LightGBM 模型
"""
import os
import csv
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# 特征列顺序 (与 features.py 中保持一致)
FEATURE_COLUMNS = [
    # 邮件头特征 (8 维)
    'is_suspicious_from_domain', 'received_hops_count',
    'first_external_ip_is_blacklisted',
    'spf_fail', 'dkim_fail', 'dmarc_fail',
    'from_display_name_mismatch', 'from_domain_in_subject',

    # URL 特征 (14 维)
    'avg_domain_age_days', 'max_vt_detection_ratio',
    'min_has_https', 'short_url_count', 'mixed_sld_count',
    'max_domain_length',
    'ip_address_count', 'port_count',
    'at_symbol_count', 'subdomain_count', 'suspicious_param_count',
    'avg_url_length', 'avg_path_depth', 'max_query_length',

    # 文本特征 (7 维)
    'urgent_keywords_count', 'financial_keywords_count',
    'text_length', 'urgency_score', 'exclamation_count',
    'caps_ratio', 'url_count',

    # 附件特征 (5 维)
    'attachment_count', 'has_suspicious_attachment',
    'has_executable_attachment', 'total_attachment_size',
    'has_double_extension',

    # HTML 特征 (5 维)
    'has_html_body', 'html_link_count', 'has_hidden_links',
    'has_form', 'has_iframe',
]

def load_example_data():
    """
    加载 example 项目的数据集
    """
    phishing_file = 'data/features-phishing.csv'
    enron_file = 'data/features-enron.csv'
    
    # 加载钓鱼邮件数据
    phishing_df = pd.read_csv(phishing_file)
    phishing_df['label'] = 1  # 钓鱼邮件
    
    # 加载正常邮件数据
    enron_df = pd.read_csv(enron_file)
    enron_df['label'] = 0  # 正常邮件
    
    # 合并数据集
    combined_df = pd.concat([phishing_df, enron_df], ignore_index=True)
    
    return combined_df

def map_features(example_df):
    """
    将 example 项目的特征映射到当前项目的特征体系
    """
    # 创建特征映射字典
    mapped_features = []
    
    for _, row in example_df.iterrows():
        feature_vector = {
            # 邮件头特征 (设置默认值)
            'is_suspicious_from_domain': 0,
            'received_hops_count': 0,
            'first_external_ip_is_blacklisted': 0,
            'spf_fail': 0,
            'dkim_fail': 0,
            'dmarc_fail': 0,
            'from_display_name_mismatch': 0,
            'from_domain_in_subject': 0,
            
            # URL 特征
            'avg_domain_age_days': 3650,  # 默认值
            'max_vt_detection_ratio': 0,
            'min_has_https': 1,  # 默认值
            'short_url_count': 0,
            'mixed_sld_count': 0,
            'max_domain_length': 0,
            'ip_address_count': 1 if row['IPs in URLs'] else 0,
            'port_count': 0,
            'at_symbol_count': 1 if row['@ in URLs'] else 0,
            'subdomain_count': 0,
            'suspicious_param_count': 0,
            'avg_url_length': 0,
            'avg_path_depth': 0,
            'max_query_length': 0,
            
            # 文本特征
            'urgent_keywords_count': 0,
            'financial_keywords_count': 0,
            'text_length': 0,
            'urgency_score': 0,
            'exclamation_count': 0,
            'caps_ratio': 0,
            'url_count': row['URLs'],
            
            # 附件特征
            'attachment_count': row['Attachments'],
            'has_suspicious_attachment': 1 if row['Attachments'] > 0 else 0,
            'has_executable_attachment': 0,
            'total_attachment_size': 0,
            'has_double_extension': 0,
            
            # HTML 特征
            'has_html_body': 1 if row['HTML content'] else 0,
            'html_link_count': row['URLs'],
            'has_hidden_links': 0,
            'has_form': 1 if row['Html Form'] else 0,
            'has_iframe': 1 if row['Html iFrame'] else 0,
        }
        
        mapped_features.append(feature_vector)
    
    return pd.DataFrame(mapped_features)

def train_model(X, y):
    """
    训练 LightGBM 模型
    """
    # 划分训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 创建 LightGBM 数据集
    train_data = lgb.Dataset(X_train, label=y_train)
    test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    
    # 设置参数 - 二分类
    params = {
        'boosting_type': 'gbdt',
        'objective': 'binary',
        'metric': 'binary_logloss',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.9,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'verbose': 1
    }
    
    # 训练模型
    print("开始训练模型...")
    model = lgb.train(
        params,
        train_data,
        num_boost_round=100,
        valid_sets=[test_data]
    )
    
    # 评估模型
    y_pred = model.predict(X_test, num_iteration=model.best_iteration)
    y_pred_class = [1 if pred > 0.5 else 0 for pred in y_pred]
    
    print("\n模型评估结果:")
    print(f"准确率: {accuracy_score(y_test, y_pred_class):.4f}")
    print(f"精确率: {precision_score(y_test, y_pred_class):.4f}")
    print(f"召回率: {recall_score(y_test, y_pred_class):.4f}")
    print(f"F1 分数: {f1_score(y_test, y_pred_class):.4f}")
    
    return model

def save_model(model, model_path='models/phish_detector.txt'):
    """
    保存模型
    """
    # 确保模型目录存在
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # 保存模型
    model.save_model(model_path)
    print(f"模型已保存到: {model_path}")

def main():
    """
    主函数
    """
    # 加载数据
    print("加载数据...")
    example_df = load_example_data()
    
    # 映射特征
    print("映射特征...")
    mapped_df = map_features(example_df)
    
    # 准备训练数据
    X = mapped_df[FEATURE_COLUMNS]
    y = example_df['label'].astype(int)
    
    # 训练模型
    model = train_model(X, y)
    
    # 保存模型
    save_model(model)
    
    print("\n训练完成！")

if __name__ == "__main__":
    main()
