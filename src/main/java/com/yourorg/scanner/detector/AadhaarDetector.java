package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds candidate Aadhaar numbers: 12 digits, optionally grouped in
 * blocks of 4 with spaces or hyphens. Verhoeff checksum validation
 * happens later, in the validator layer.
 */
@Component
public class AadhaarDetector implements SensitiveDataDetector {

    private static final Pattern AADHAAR_PATTERN =
            Pattern.compile("\\b\\d{4}[ -]?\\d{4}[ -]?\\d{4}\\b");

    @Override
    public SensitiveDataType getType() {
        return SensitiveDataType.AADHAAR_NUMBER;
    }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return candidates;
        }

        Matcher matcher = AADHAAR_PATTERN.matcher(text);
        while (matcher.find()) {
            candidates.add(matcher.group());
        }
        return candidates;
    }
}