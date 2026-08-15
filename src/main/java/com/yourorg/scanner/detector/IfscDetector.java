package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** IFSC: 4 letters + literal '0' (reserved) + 6 alphanumeric. Structurally well-defined. */
@Component
public class IfscDetector implements SensitiveDataDetector {

    private static final Pattern IFSC_PATTERN = Pattern.compile("\\b[A-Z]{4}0[A-Z0-9]{6}\\b");

    @Override
    public SensitiveDataType getType() { return SensitiveDataType.IFSC; }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) return candidates;
        Matcher matcher = IFSC_PATTERN.matcher(text);
        while (matcher.find()) candidates.add(matcher.group());
        return candidates;
    }
}