package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Standard email address format. */
@Component
public class EmailDetector implements SensitiveDataDetector {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");

    @Override
    public SensitiveDataType getType() { return SensitiveDataType.EMAIL; }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) return candidates;
        Matcher matcher = EMAIL_PATTERN.matcher(text);
        while (matcher.find()) candidates.add(matcher.group());
        return candidates;
    }
}