package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Indian mobile number: 10 digits starting 6-9, optional +91/91 prefix. */
@Component
public class PhoneNumberDetector implements SensitiveDataDetector {

    private static final Pattern PHONE_PATTERN =
            Pattern.compile("\\b(?:(?:\\+91|91)[-\\s]?)?[6-9]\\d{9}\\b");

    @Override
    public SensitiveDataType getType() { return SensitiveDataType.PHONE_NUMBER; }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) return candidates;
        Matcher matcher = PHONE_PATTERN.matcher(text);
        while (matcher.find()) candidates.add(matcher.group());
        return candidates;
    }
}