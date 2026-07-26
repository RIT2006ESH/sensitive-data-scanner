package com.yourorg.scanner.classifier;

import com.yourorg.scanner.model.RiskLevel;
import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Maps each SensitiveDataType to a business-defined risk level.
 * Centralized here so the risk mapping can change (or grow, for future
 * data types) without touching detectors, the orchestrator, or reports.
 */
@Component
public class RiskClassifier {

    private static final Map<SensitiveDataType, RiskLevel> RISK_MAP = Map.of(
            SensitiveDataType.CARD_NUMBER, RiskLevel.CRITICAL,
            SensitiveDataType.AADHAAR_NUMBER, RiskLevel.CRITICAL,
            SensitiveDataType.PAN_NUMBER, RiskLevel.MEDIUM
    );

    public RiskLevel classify(SensitiveDataType type) {
        return RISK_MAP.getOrDefault(type, RiskLevel.NORMAL);
    }
}