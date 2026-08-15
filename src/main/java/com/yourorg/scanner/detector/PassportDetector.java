package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Indian passport: 1 letter + 7 digits. No public checksum -- structural match only. */
@Component
public class PassportDetector implements SensitiveDataDetector {

    private static final Pattern PASSPORT_PATTERN = Pattern.compile("\\b[A-Z][0-9]{7}\\b");

    @Override
    public SensitiveDataType getType() { return SensitiveDataType.PASSPORT; }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) return candidates;
        Matcher matcher = PASSPORT_PATTERN.matcher(text);
        while (matcher.find()) candidates.add(matcher.group());
        return candidates;
    }
}