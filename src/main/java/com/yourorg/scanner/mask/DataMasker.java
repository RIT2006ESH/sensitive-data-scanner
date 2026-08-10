package com.yourorg.scanner.mask;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;


@Component
public class DataMasker {

    private static final int VISIBLE_SUFFIX_LENGTH = 4;
    private static final String MASK_CHAR = "*";


    public String mask(String rawValue, SensitiveDataType type) {
        if (rawValue == null || rawValue.isEmpty()) {
            return "";
        }

        return switch (type) {
            case CARD_NUMBER, AADHAAR_NUMBER -> maskKeepingLastFour(rawValue);
            case PAN_NUMBER -> maskPan(rawValue);
        };
    }


    private String maskKeepingLastFour(String rawValue) {
        int length = rawValue.length();

        if (length <= VISIBLE_SUFFIX_LENGTH) {
            return MASK_CHAR.repeat(length);
        }

        int visibleFrom = length - VISIBLE_SUFFIX_LENGTH;
        StringBuilder masked = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            char currentChar = rawValue.charAt(i);
            boolean isSeparator = (currentChar == ' ' || currentChar == '-');
            boolean isInVisibleSuffix = (i >= visibleFrom);

            if (isSeparator || isInVisibleSuffix) {
                masked.append(currentChar);
            } else {
                masked.append(MASK_CHAR);
            }
        }

        return masked.toString();
    }


    private String maskPan(String rawValue) {
        if (rawValue.length() != 10) {
            return MASK_CHAR.repeat(rawValue.length());
        }
        return MASK_CHAR + rawValue.substring(5, 9) + MASK_CHAR;
    }
}