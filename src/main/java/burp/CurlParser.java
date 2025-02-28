package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import burp.*;  // This will import all Burp interfaces including IExtensionHelpers
public class CurlParser {

    public static List<String> parseCURLtoHeaderList(String curlCommand) {
        try {
            // 解析方法和URL
            String method = extractMethod(curlCommand);
            String url = extractUrl(curlCommand);
            java.net.URL urlObj = new java.net.URL(url);


            String path = urlObj.getPath() + '?' + urlObj.getQuery();

            // 解析headers
            List<String> headers = extractHeaders(curlCommand);
            List<String> filteredHeaders = new ArrayList<>();
            for (String header : headers) {
                if (!header.toLowerCase().startsWith("content-length:")) {
                    filteredHeaders.add(header);
                }
            }
            // 使用Burp的helpers来构建HTTP消息
            List<String> headersList = new ArrayList<>();
            headersList.add(method + " " + path + " HTTP/1.1");
            headersList.addAll(filteredHeaders);  // 使用过滤后的headers

            return headersList;
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Error converting curl command in parseCURLtoHeaderList: " + e.getMessage());
            return null;
        }
    }

    public static byte[] parseCURLtoBodyBytes(String curlCommand) {
        try {

            // 解析请求体
            String body = extractBody(curlCommand);

            return body != null ? body.getBytes() : new byte[0];

        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Error converting curl command in parseCURLtoBodyBytes: " + e.getMessage());
            return null;
        }
    }
    private static String extractMethod(String curlCommand) {
        Pattern pattern = Pattern.compile("-X\\s+\\$?['\"](.*?)['\"]");
        Matcher matcher = pattern.matcher(curlCommand);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "GET";
    }

    public static String extractUrl(String curlCommand) {
        List<String> args = parseArguments(curlCommand);

        String urlRegex = "^(https?://)"                 // 协议部分
                + "(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\\.)+[A-Z]{2,6}\\.?|" // 域名
                + "localhost|"                           // localhost
                + "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" // IP地址
                + "(?::\\d+)?"                          // 端口
                + "(?:/?|[/?]\\S+)$";                   // 路径和参数

        Pattern pattern = Pattern.compile(urlRegex, Pattern.CASE_INSENSITIVE);

        // 优先检查 --location 参数
        for (int i = 0; i < args.size(); i++) {
            if (args.get(i).equals("--location") && i+1 < args.size()) {
                return args.get(i+1);
            }
            else if (pattern.matcher(args.get(i)).matches()) {
                return args.get(i);
            }
        }
        // 否则取最后一个参数
        return args.get(args.size() - 1);
    }
    private static List<String> parseArguments(String command) {
        List<String> args = new ArrayList<>();
        Matcher m = Pattern.compile("(['\"])(.*?)\\1|(\\S+)").matcher(command);

        while (m.find()) {
            String arg = m.group(2) != null ? m.group(2) : m.group(3);
            args.add(arg.replace("$'", "")); // 清理shell特殊格式
        }
        return args;
    }

    private static List<String> extractHeaders(String curlCommand) {
        List<String> headers = new ArrayList<>();
        Pattern pattern = Pattern.compile("-H\\s+\\$?['\"](.*?)['\"]");
        Matcher matcher = pattern.matcher(curlCommand);

        while (matcher.find()) {
            headers.add(matcher.group(1));
        }

        Pattern pattern2 = Pattern.compile("-b\\s+\\$?'((?:[^']|\\\\')*)'");
        Matcher matcher2 = pattern2.matcher(curlCommand);
        if (matcher2.find()) {
            headers.add("cookie: "+matcher2.group(1));
        }

        Collections.sort(headers);

        return headers;
    }

    private static String extractBody(String curlCommand) {
        // 改进正则表达式匹配数据部分
        Pattern pattern = Pattern.compile("--data-binary\\s+\\$?'((?:[^']|\\\\')*)'");
        Matcher matcher = pattern.matcher(curlCommand);
        if (matcher.find()) {
            String body = matcher.group(1)
                    .replace("\\\"", "\"")    // 处理转义双引号
                    .replace("\\\\", "\\")    // 处理转义反斜杠
                    .replace("\\n", "\n")     // 处理换行符
                    .replace("\\r", "\r")     // 处理回车符
                    .replace("\\t", "\t");    // 处理制表符
            return body;
        }
        return null;
    }
}
