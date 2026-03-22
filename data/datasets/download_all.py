#!/usr/bin/env python3
"""
完整数据集下载脚本
运行此脚本下载所有推荐的数据集
"""

import subprocess
import os
from pathlib import Path

DATASETS_DIR = Path(__file__).parent

def download_kaggle_dataset(kaggle_id: str, dest_name: str):
    """下载Kaggle数据集"""
    dest_dir = DATASETS_DIR / dest_name
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    cmd = f"kaggle datasets download -d {kaggle_id} -p {dest_dir} --unzip"
    print(f"下载: {kaggle_id}")
    subprocess.run(cmd, shell=True)

def main():
    print("开始下载所有数据集...")
    
    # Kaggle钓鱼邮件数据集
    datasets = [
        ("naserabdullahalam/phishing-email-dataset", "phishing_emails"),
        ("subhajournal/phishingemails", "phishing_emails_2"),
        ("balaka18/email-spam-classification-dataset-csv", "spam_classification"),
    ]
    
    for kaggle_id, dest_name in datasets:
        try:
            download_kaggle_dataset(kaggle_id, dest_name)
        except Exception as e:
            print(f"下载失败 {kaggle_id}: {e}")
    
    print("\n所有数据集下载完成!")

if __name__ == "__main__":
    main()
