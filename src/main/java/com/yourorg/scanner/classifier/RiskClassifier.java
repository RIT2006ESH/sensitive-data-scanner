package com.yourorg.scanner.classifier;

import com.yourorg.scanner.model.RiskLevel;
import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class RiskClassifier {

    private static final Map<SensitiveDataType, RiskLevel> RISK_MAP = Map.ofEntries(
            Map.entry(SensitiveDataType.CARD_NUMBER, RiskLevel.CRITICAL),
            Map.entry(SensitiveDataType.AADHAAR_NUMBER, RiskLevel.CRITICAL),
            Map.entry(SensitiveDataType.BANK_ACCOUNT, RiskLevel.CRITICAL),
            Map.entry(SensitiveDataType.PASSPORT, RiskLevel.CRITICAL),
            Map.entry(SensitiveDataType.PAN_NUMBER, RiskLevel.MEDIUM),
            Map.entry(SensitiveDataType.DRIVING_LICENCE, RiskLevel.MEDIUM),
            Map.entry(SensitiveDataType.VOTER_ID, RiskLevel.MEDIUM),
            Map.entry(SensitiveDataType.IFSC, RiskLevel.MEDIUM),
            Map.entry(SensitiveDataType.UPI_ID, RiskLevel.MEDIUM),
            Map.entry(SensitiveDataType.PHONE_NUMBER, RiskLevel.NORMAL),
            Map.entry(SensitiveDataType.EMAIL, RiskLevel.NORMAL)
    );

    public RiskLevel classify(SensitiveDataType type) {
        return RISK_MAP.getOrDefault(type, RiskLevel.NORMAL);
    }
}