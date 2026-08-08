package com.yourorg.scanner.classifier;

import com.yourorg.scanner.model.RiskLevel;
import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.Map;


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