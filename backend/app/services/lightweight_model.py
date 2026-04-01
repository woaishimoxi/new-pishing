"""
轻量模型服务
支持三种模型：
- RF分类器 (35维)
- XGB分类器 (35维)
- 异常检测器 (26维)
"""
import os
import joblib
import numpy as np
from typing import List, Optional, Tuple, Dict
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger

logger = get_logger(__name__)

# 模型路径
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_MODELS_DIR = os.path.join(_BASE_DIR, 'models')

# 模型文件路径
_PHISHMMF_RF_PATH = os.path.join(_MODELS_DIR, 'phishmmf_simplified_rf.joblib')
_PHISHMMF_XGB_PATH = os.path.join(_MODELS_DIR, 'phishmmf_simplified_xgb.joblib')
_PHISHMMF_SCALER_PATH = os.path.join(_MODELS_DIR, 'phishmmf_simplified_scaler.joblib')
_IFOREST_PATH = os.path.join(_MODELS_DIR, 'phish_iforest.joblib')
_IFOREST_SCALER_PATH = os.path.join(_MODELS_DIR, 'phish_iforest_scaler.joblib')

# 全局模型缓存
_models = {
    'phishmmf_rf': None,
    'phishmmf_xgb': None,
    'phishmmf_scaler': None,
    'iforest': None,
    'iforest_scaler': None,
}
_models_loaded = False


def load_models():
    """加载所有模型"""
    global _models, _models_loaded
    
    if _models_loaded:
        return
    
    logger.info(f"正在加载轻量模型: {_MODELS_DIR}")
    
    # 加载RF分类器
    if os.path.exists(_PHISHMMF_RF_PATH):
        try:
            _models['phishmmf_rf'] = joblib.load(_PHISHMMF_RF_PATH)
            logger.info("加载RF分类器成功")
        except Exception as e:
            logger.error(f"加载RF分类器失败: {e}")
    
    # 加载XGB分类器
    if os.path.exists(_PHISHMMF_XGB_PATH):
        try:
            _models['phishmmf_xgb'] = joblib.load(_PHISHMMF_XGB_PATH)
            logger.info("加载XGB分类器成功")
        except Exception as e:
            logger.error(f"加载XGB分类器失败: {e}")
    
    # 加载标准化器
    if os.path.exists(_PHISHMMF_SCALER_PATH):
        try:
            _models['phishmmf_scaler'] = joblib.load(_PHISHMMF_SCALER_PATH)
            logger.info("加载标准化器成功")
        except Exception as e:
            logger.error(f"加载标准化器失败: {e}")
    
    # 加载异常检测器
    if os.path.exists(_IFOREST_PATH):
        try:
            _models['iforest'] = joblib.load(_IFOREST_PATH)
            logger.info("加载异常检测器成功")
        except Exception as e:
            logger.error(f"加载异常检测器失败: {e}")
    
    # 加载异常检测器标准化器
    if os.path.exists(_IFOREST_SCALER_PATH):
        try:
            _models['iforest_scaler'] = joblib.load(_IFOREST_SCALER_PATH)
            logger.info("加载异常检测器标准化器成功")
        except Exception as e:
            logger.error(f"加载异常检测器标准化器失败: {e}")
    
    _models_loaded = True
    
    # 输出模型状态
    for name, model in _models.items():
        logger.info(f"{name}: {'可用' if model is not None else '不可用'}")


def is_models_available() -> Dict[str, bool]:
    """检查模型可用性"""
    load_models()
    return {
        'rf': _models['phishmmf_rf'] is not None,
        'xgb': _models['phishmmf_xgb'] is not None,
        'iforest': _models['iforest'] is not None,
    }


def score_with_rf(features_35: List[float]) -> Optional[float]:
    """
    使用RF分类器评分 (35维特征)
    返回钓鱼概率 (0-1)
    """
    load_models()
    
    if _models['phishmmf_rf'] is None:
        return None
    
    try:
        X = np.array(features_35, dtype=float).reshape(1, -1)
        
        if _models['phishmmf_scaler'] is not None:
            X = _models['phishmmf_scaler'].transform(X)
        
        proba = float(_models['phishmmf_rf'].predict_proba(X)[0, 1])
        return 1.0 - proba
    except Exception as e:
        logger.error(f"RF评分错误: {e}")
        return None


def score_with_xgb(features_35: List[float]) -> Optional[float]:
    """
    使用XGB分类器评分 (35维特征)
    返回钓鱼概率 (0-1)
    """
    load_models()
    
    if _models['phishmmf_xgb'] is None:
        return None
    
    try:
        X = np.array(features_35, dtype=float).reshape(1, -1)
        
        if _models['phishmmf_scaler'] is not None:
            X = _models['phishmmf_scaler'].transform(X)
        
        proba = float(_models['phishmmf_xgb'].predict_proba(X)[0, 1])
        return 1.0 - proba
    except Exception as e:
        logger.error(f"XGB评分错误: {e}")
        return None


def score_with_anomaly_detector(features_26: List[float]) -> Optional[float]:
    """
    使用异常检测器评分 (26维特征)
    返回异常分数 (0-1)，越大越异常
    """
    load_models()
    
    if _models['iforest'] is None:
        return None
    
    try:
        X = np.array(features_26, dtype=float).reshape(1, -1)
        
        if _models['iforest_scaler'] is not None:
            try:
                X = _models['iforest_scaler'].transform(X)
            except Exception as e:
                logger.debug(f"标准化器转换失败: {e}")
        
        df = float(_models['iforest'].decision_function(X)[0])
        
        # 归一化到 [0, 1] 并反转
        df_clipped = max(min(df, 0.5), -0.5)
        normalized = (df_clipped + 0.5) / 1.0
        phishing_score = 1.0 - normalized
        
        return float(phishing_score)
    except Exception as e:
        logger.error(f"异常检测器评分错误: {e}")
        return None


def ensemble_score(features_35: List[float], features_26: List[float]) -> Tuple[Optional[float], Dict]:
    """
    集成评分：融合多个模型的结果
    
    Args:
        features_35: 35维特征（用于RF/XGB分类器）
        features_26: 26维特征（用于异常检测器）
    
    Returns:
        (final_score, detail_scores)
    """
    scores = {}
    weights = {}
    
    # RF分类器 (35维)
    rf_score = score_with_rf(features_35)
    if rf_score is not None:
        scores['rf'] = rf_score
        weights['rf'] = 1.5
    
    # XGB分类器 (35维)
    xgb_score = score_with_xgb(features_35)
    if xgb_score is not None:
        scores['xgb'] = xgb_score
        weights['xgb'] = 1.5
    
    # 异常检测器 (26维)
    anomaly_score = score_with_anomaly_detector(features_26)
    if anomaly_score is not None:
        scores['anomaly'] = anomaly_score
        weights['anomaly'] = 1.0
    
    if not scores:
        return None, {}
    
    # 加权平均
    total_weight = sum(weights.values())
    final_score = sum(scores[k] * weights[k] for k in scores) / total_weight
    
    detail_scores = {
        'scores': scores,
        'weights': weights,
        'final_score': final_score
    }
    
    return final_score, detail_scores
    
    return final_score, detail_scores
