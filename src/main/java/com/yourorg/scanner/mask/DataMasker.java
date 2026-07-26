package com.yourorg.scanner.mask;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

/**
 * Masks a confirmed sensitive value before it is ever logged, stored, or
 * written to the report. This is the ONLY place in the codebase that should
 * ever produce a human-readable representation of a detected value —
 * everywhere else (ScanResult, reports, logs) should only ever see the
 * output of this class, never the raw candidate string.
 */
@Component
public class DataMasker {

    private static final int VISIBLE_SUFFIX_LENGTH = 4;
    private static final String MASK_CHAR = "*";

    /**
     * @param rawValue the confirmed-valid value (digits/letters, may still
     *                  contain spaces/hyphens as originally matched)
     * @param type      which kind of sensitive data this is
     * @return a masked string, e.g. "**** **** **** 1234"
     */
    public String mask(String rawValue, SensitiveDataType type) {
        if (rawValue == null || rawValue.isEmpty()) {
            return "";
        }

        return switch (type) {
            case CARD_NUMBER, AADHAAR_NUMBER -> maskKeepingLastFour(rawValue);
            case PAN_NUMBER -> maskPan(rawValue);
        };
    }

    /**
     * Masks every character except the last 4 digits, preserving any
     * grouping characters (spaces/hyphens) in their original position.
     * E.g. "4111-1111-1111-1234" -> "****-****-****-1234".
     * If the value is too short to meaningfully mask, it is fully masked.
     */
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

    /**
     * PAN numbers are 10 characters: 5 letters + 4 digits + 1 letter.
     * The identifying letters are masked; the 4-digit middle section is
     * kept visible since it alone is not identifying.
     * E.g. "ABCDE1234F" -> "*****1234*".
     */
    private String maskPan(String rawValue) {
        if (rawValue.length() != 10) {
            return MASK_CHAR.repeat(rawValue.length());
        }
        return MASK_CHAR + rawValue.substring(5, 9) + MASK_CHAR;
    }
}