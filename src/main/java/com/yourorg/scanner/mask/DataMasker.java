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
            case CARD_NUMBER, AADHAAR_NUMBER, BANK_ACCOUNT, PHONE_NUMBER,
                 PASSPORT, DRIVING_LICENCE, VOTER_ID, IFSC -> maskKeepingLastFour(rawValue);
            case PAN_NUMBER -> maskPan(rawValue);
            case UPI_ID, EMAIL -> maskEmailLike(rawValue);
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


    /** For email-shaped values (email addresses, UPI IDs): mask the local part, keep the domain/handle visible. */
    private String maskEmailLike(String rawValue) {
        int atIndex = rawValue.indexOf('@');
        if (atIndex <= 0) {
            return MASK_CHAR.repeat(rawValue.length());
        }

        String localPart = rawValue.substring(0, atIndex);
        String domainPart = rawValue.substring(atIndex);

        String maskedLocal = localPart.length() <= 2
                ? MASK_CHAR.repeat(localPart.length())
                : localPart.charAt(0) + MASK_CHAR.repeat(localPart.length() - 2) + localPart.charAt(localPart.length() - 1);

        return maskedLocal + domainPart;
    }
}