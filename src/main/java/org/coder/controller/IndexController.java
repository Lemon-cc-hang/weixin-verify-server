package org.coder.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author lemoncc
 */
@RestController
public class IndexController {

    @Value("${weixin.mp.token")
    private String token;

    /**
     * 验证微信签名
     */
    @GetMapping
    public String verifySign(String signature,String timestamp,String nonce,String echostr){
        boolean checkSignature = checkSignature(signature, timestamp, nonce);
        if(checkSignature){
            return echostr;
        }else {
            return null;
        }
    }

    /**
     * 验证微信签名
     */
    public boolean checkSignature(String signature, String timestamp,
        String nonce) {

        // 1.将token、timestamp、nonce三个参数进行字典序排序
        String[] arr = new String[] { token, timestamp, nonce };
        Arrays.sort(arr);
        // 2. 将三个参数字符串拼接成一个字符串进行sha1加密
        String content = String.join("", arr);
        MessageDigest md;
        String tmpStr;
        try {
            md = MessageDigest.getInstance("SHA-1");
            // 将三个参数字符串拼接成一个字符串进行sha1加密
            byte[] digest = md.digest(content.getBytes(StandardCharsets.UTF_8));
            tmpStr = byteToStr(digest);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            return false;
        }
        // 3.将sha1加密后的字符串可与signature对比，标识该请求来源于微信
        return tmpStr.equals(signature.toUpperCase());
    }

    private static String byteToStr(byte[] byteArray) {
        StringBuilder strDigest = new StringBuilder();
        for (byte b : byteArray) {
            strDigest.append(byteToHexStr(b));
        }
        return strDigest.toString();
    }

    private static String byteToHexStr(byte mByte) {
        char[] Digit = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
            'B', 'C', 'D', 'E', 'F' };
        char[] tempArr = new char[2];
        tempArr[0] = Digit[(mByte >>> 4) & 0X0F];
        tempArr[1] = Digit[mByte & 0X0F];
        return new String(tempArr);
    }
}