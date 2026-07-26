package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds candidate PAN numbers matching the standard Indian Income Tax
 * Department format: 5 letters, 4 digits, 1 letter (e.g. AAAAA9999A).
 */
@Component
public class PanNumberDetector implements SensitiveDataDetector {

    private static final Pattern PAN_PATTERN =
            Pattern.compile("\\b[A-Z]{5}[0-9]{4}[A-Z]\\b");

    @Override
    public SensitiveDataType getType() {
        return SensitiveDataType.PAN_NUMBER;
    }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return candidates;
        }

        Matcher matcher = PAN_PATTERN.matcher(text);
        while (matcher.find()) {
            candidates.add(matcher.group());
        }
        return candidates;
    }
}