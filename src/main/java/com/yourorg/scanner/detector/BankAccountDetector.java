package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class BankAccountDetector implements SensitiveDataDetector {

    private static final Pattern BANK_ACCOUNT_PATTERN = Pattern.compile("\\b\\d{9,18}\\b");

    @Override
    public SensitiveDataType getType() { return SensitiveDataType.BANK_ACCOUNT; }

    @Override
    public List<String> detectCandidates(String text) {
        List<String> candidates = new ArrayList<>();
        if (text == null || text.isEmpty()) return candidates;
        Matcher matcher = BANK_ACCOUNT_PATTERN.matcher(text);
        while (matcher.find()) candidates.add(matcher.group());
        return candidates;
    }
}