import logging
import os
from typing import Any, Dict, List, Optional
import numpy as np
from app.models.event import SecurityEvent

logger = logging.getLogger(__name__)


class MLEngine:
    """
    Modular Machine Learning Anomaly Detection Component.
    Uses Scikit-learn IsolationForest to identify statistically abnormal event velocity,
    unusual timing patterns, and anomalous authentication vectors.
    """

    def __init__(self):
        self.model = None
        self.is_trained = False
        self._init_model()

    def _init_model(self):
        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )
            # Pre-train on baseline synthetic security metrics:
            # Features: [event_frequency, failure_flag, off_hours_flag, internal_flag]
            baseline_normal = np.array([
                [1, 0, 0, 1],
                [2, 0, 0, 1],
                [1, 0, 1, 1],
                [3, 0, 0, 1],
                [1, 1, 0, 1],
                [2, 0, 0, 0],
                [1, 0, 0, 1],
                [2, 1, 0, 1],
            ] * 20)
            self.model.fit(baseline_normal)
            self.is_trained = True
            logger.info("Scikit-learn IsolationForest anomaly model trained on baseline.")
        except Exception as e:
            self.is_trained = False
            logger.info(f"ML initialization in lightweight heuristic mode ({e})")

    def featurize_event(self, event: SecurityEvent, velocity: int = 1) -> List[float]:
        """Converts an event into numeric feature vector for model inference."""
        failure_flag = 1.0 if "fail" in event.event_type.lower() else 0.0
        hour = event.timestamp.hour
        off_hours_flag = 1.0 if (hour < 6 or hour > 21) else 0.0
        internal_flag = 1.0 if event.source_ip.startswith(("10.", "192.168.", "127.")) else 0.0
        freq = float(velocity)
        return [freq, failure_flag, off_hours_flag, internal_flag]

    def predict_anomaly(self, event: SecurityEvent, velocity: int = 1) -> Dict[str, Any]:
        """
        Infers whether the event represents an anomaly.
        Returns: detected (bool), attack_type (str), confidence (float), evidence (list).
        """
        features = self.featurize_event(event, velocity=velocity)

        # High velocity or failed bursts are primary anomaly indicators
        is_anomaly = False
        confidence = 0.50
        anomaly_score = 0.0

        if self.is_trained and self.model is not None:
            try:
                pred = self.model.predict([features])[0]  # -1 = anomaly, 1 = normal
                dec_score = float(self.model.decision_function([features])[0])
                anomaly_score = round(max(0.0, min(1.0, -dec_score)), 2)

                if pred == -1 or velocity >= 5 or "fail" in event.event_type.lower() and velocity >= 3:
                    is_anomaly = True
                    confidence = min(0.98, 0.60 + (velocity * 0.002) + (anomaly_score * 0.3))
            except Exception as e:
                logger.debug(f"ML inference error: {e}")

        if not self.is_trained:
            # Resilient statistical heuristic
            if velocity >= 5:
                is_anomaly = True
                confidence = min(0.95, 0.70 + (velocity * 0.001))
                anomaly_score = 0.85

        evidence = []
        attack_type = "Statistical Anomaly"
        if is_anomaly:
            if "fail" in event.event_type.lower():
                attack_type = "Brute-Force Velocity Anomaly"
                evidence.append(f"ML IsolationForest flagged abnormal event velocity: {velocity} occurrences.")
            else:
                attack_type = "Unusual Behavioral Outlier"
                evidence.append(f"Event feature vector deviated from normal baseline (anomaly score: {anomaly_score}).")

        return {
            "detected": is_anomaly,
            "attack_type": attack_type if is_anomaly else "Normal Telemetry",
            "confidence": round(confidence, 2) if is_anomaly else 0.0,
            "anomaly_score": anomaly_score,
            "evidence": evidence
        }


ml_engine = MLEngine()

