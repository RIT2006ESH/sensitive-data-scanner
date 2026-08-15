package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class UpiIdDetector implements SensitiveDataDetector {

    private static final Pattern UPI_PATTERN =
            Pattern.compile("\\b[a-zA-Z0-9.\\-_]{2,256}@[a-zA-Z]{3,64}\\b(?!\\.)");

    @Override
    public SensitiveDataType getType() { return SensitiveDataType.UPI_ID; }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) return candidates;
        Matcher matcher = UPI_PATTERN.matcher(text);
        while (matcher.find()) candidates.add(matcher.group());
        return candidates;
    }
}