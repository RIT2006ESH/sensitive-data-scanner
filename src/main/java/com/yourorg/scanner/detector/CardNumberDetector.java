package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@Component
public class CardNumberDetector implements SensitiveDataDetector {

    private static final Pattern CARD_PATTERN = Pattern.compile(
            "\\b(?:\\d{13,19}|\\d{4}[ -]\\d{4}[ -]\\d{4}[ -]\\d{1,7})\\b"
    );

    @Override
    public SensitiveDataType getType() {
        return SensitiveDataType.CARD_NUMBER;
    }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return candidates;
        }

        Matcher matcher = CARD_PATTERN.matcher(text);
        while (matcher.find()) {
            candidates.add(matcher.group());
        }
        return candidates;
    }
}