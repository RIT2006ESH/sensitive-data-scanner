package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class DrivingLicenceDetector implements SensitiveDataDetector {

    private static final Pattern DL_PATTERN =
            Pattern.compile("\\b[A-Z]{2}[- ]?\\d{2}[- ]?\\d{4}[- ]?\\d{7}\\b");

    @Override
    public SensitiveDataType getType() { return SensitiveDataType.DRIVING_LICENCE; }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) return candidates;
        Matcher matcher = DL_PATTERN.matcher(text);
        while (matcher.find()) candidates.add(matcher.group());
        return candidates;
    }
}