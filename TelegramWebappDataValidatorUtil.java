package ua.te.seller.util;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

@Slf4j
@UtilityClass
public class TelegramWebappDataValidatorUtil {

    public static boolean isValid(String initData, String telegramBotToken) {
        Map<String, String> initDataMap = parseInitData(initData);
        String hash = initDataMap.get("hash");
        initDataMap.remove("hash");

        String dataCheckString = new TreeMap<>(initDataMap)
                .entrySet()
                .stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining("\n"));

        String secret = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, "WebAppData")
                .hmacHex(telegramBotToken);

        String dataCheckHash = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, secret)
                .hmacHex(dataCheckString);
        return hash.equals(dataCheckHash);
    }

    private static Map<String, String> parseInitData(String initData) {
        Map<String, String> initDataMap = new HashMap<>();
        String[] keyValuePairs = initData.split("&");

        for (String keyValuePair : keyValuePairs) {
            String[] parts = keyValuePair.split("=", 2);
            if (parts.length == 2) {
                initDataMap.put(parts[0], parts[1]);
            }
        }
        return initDataMap;
    }
}
