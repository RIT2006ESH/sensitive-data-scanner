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
            "\\b(?:" +
                    "4\\d{12}(?:\\d{3})?" +                 // Visa: 13 or 16 digits, starts with 4
                    "|5[1-5]\\d{14}" +                       // Mastercard: 16 digits, starts with 51-55
                    "|2(?:2[2-9][1-9]|[3-6]\\d{2}|7(?:[01]\\d|20))\\d{12}" + // Mastercard: newer 2221-2720 range
                    "|3[47]\\d{13}" +                        // Amex: 15 digits, starts with 34 or 37
                    "|3(?:0[0-5]|[68]\\d)\\d{11}" +          // Diners Club: 14 digits
                    "|6(?:011|5\\d{2})\\d{12}" +             // Discover: 16 digits
                    "|\\d{4}[ -]\\d{4}[ -]\\d{4}[ -]\\d{1,7}" + // any explicitly grouped/separated format
                    ")\\b"
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