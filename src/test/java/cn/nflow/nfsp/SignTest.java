package cn.nflow.nfsp;

import cn.nflow.nfsp.util.RSATool;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Map;

public class SignTest {
    static Log log = LogFactory.getLog(SignTest.class);

    public static void main(String[] args) throws Exception{
        String privateKey ="MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKdkFSECX43pcYa0FFxh1cVFcH136z7Qy+MASfX8pKxpg8ghj7CBy75l5NvhmNbCDIgW065F4AuJF1b8gbSIymIbiCfOH4j3D1ESNkBhUmnGVp/ck4lKf7TOXq++n7yYgOBu3dlDGLiLO4KvupNUFUpP7g0BvxOOBH9p5ORUyJylAgMBAAECgYEAh6shSODAi6eCINhBjGKrPTk7pCWWoBHgvjpUt6+t1COs8H7rE/cPKGEzbVdaZe1e9MnzhVMS9KaHKTR899LKnAp13yxonx62Z090UumM0kvCc4RBx5HF4dUbPxa6mQlAfjpbqNbR/lOzLshYayDkoygXMCocI4R92KLJZnhMKx0CQQDjygDvw5c+P8Y93h5Ehe2W5U9h3pSP8ekFtBxUot0m3zqTvHAVw78JfnkAT33T96XSP+I+W8C7NT3sqcU0B2I/AkEAvB8rzqmyCiNZbgWtuwpSFq0at/ny2yftV6l2Kg7XW34hW469yqXMOoW2PyQfnEDiAkxX6okk8q30+c05mS7AGwJACIFPXaRw7jsVXNQBT0+s2lh/iUj1RRakO7lI4YQfO8dT+ZYsnTNs257kR7WwHgz+HQaTnP5yCMtpH4ALQ/EOowJBAIsCzbBNHU74iCEQ+Sv5mGdBSzkf7iGcA3p/st2pUeI99hBeDkks8xlbrSxDWUhxeZERMPYSmcbqXNgqmqFjNnkCQF07GR8C3KpH8rHraROkQYLPazMaGHvCz0WzCbvCRdyDghMhCtBDk3Uy5gOdzLwMjqr8LoLtWcFhqWkTJfBUkeU=";
        String publicKey ="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnZBUhAl+N6XGGtBRcYdXFRXB9d+s+0MvjAEn1/KSsaYPIIY+wgcu+ZeTb4ZjWwgyIFtOuReALiRdW/IG0iMpiG4gnzh+I9w9REjZAYVJpxlaf3JOJSn+0zl6vvp+8mIDgbt3ZQxi4izuCr7qTVBVKT+4NAb8TjgR/aeTkVMicpQIDAQAB";
        test(publicKey,privateKey);

    }



    public static void test(String publiKey, String privateKey)throws Exception {
        if (publiKey == null||privateKey ==null){
            System.out.println(JSONObject.toJSONString(RSATool.generatePaireKey(2048,"RSA")));
            Map<String,String> paire = RSATool.generatePaireKey(2048,"RSA");
            publiKey =paire.get("public");
            privateKey =paire.get("private");
        }

        String requestStr ="{\"pubData\":{\"licenseNo\":\"\",\"purpose\":\"02\",\"organNo\":\"JYXXSZ2020022101\",\"riskId\":\"\",\"commercialProposalNo\":\"\",\"deviceIMEI\":\"01 147200 197569 5\",\"applyIdentifyNo\":\"\",\"deviceMac\":\"00-23-5A-15-99-42\",\"accidentProposalNo\":\"\",\"applyName\":\"\",\"fileList\":[],\"productNo\":\"P0003\",\"outCreditId\":\"LC20022210222780315257582\",\"deviceType\":\"web\",\"deviceIP\":\"192.168.1.1\",\"amount\":9.00,\"period\":3,\"deviceOS\":\"IOS\",\"userId\":\"93ee942ea51549f99580d6a72569a99b\",\"signBase64\":\"\",\"insurePhone\":\"\",\"insurantPhone\":\"\",\"deviceGPS\":\"1024\",\"applyNo\":\"\",\"applyDate\":\"\",\"device\":\"iphone7\"},\"pubVersion\":\"1.0\",\"pubNotifyUrl\":\"\",\"pubSign\":\"jusREq2JsE1CY7r4wnLjsWyZcvSaGlOo0D0qTgJC5WYk8hz96ztINdBR9dIrMtcHew/NpxsCvQyTofWK/7zlSciJTqALmY7vTJXEQErwqyE7cSVLJgY0f96k6zR5NzUfBog9bEubnyQXvJO7QUJnQ1OEWwJeTcF1Sonr3e+57R0=\",\"pubMerNo\":\"10011\"}";
        Map<String,Object> request =JSONObject.parseObject(requestStr,Map.class);
        log.info("开始签名");
        String pubSign =sign(request,privateKey);

        log.info("结束签名");
        request.put("pubSign",pubSign);

        log.info("请求参数:"+JSONObject.toJSONString(request));
        log.info("开始验证签名");
        verify(request,publiKey);
        log.info("结束验证签名");


    }

    public static void verify(Map<String,Object> request,String publicKey){
        log.info("公钥："+publicKey);
        String pubData =JSONObject.toJSONString(request.get("pubData")) ;
        String pubSign = (String) request.get("pubSign");

        JSONObject jo = JSON.parseObject(pubData);
        pubData = JSON.toJSONString(jo, SerializerFeature.SortField, SerializerFeature.MapSortField, SerializerFeature.WriteMapNullValue,
                SerializerFeature.WriteNullStringAsEmpty, SerializerFeature.WriteNullListAsEmpty);


        System.out.println("验签字符串");
        System.out.println(pubData);
        boolean status = false;
        try {
            status = RSATool.verify(pubData, publicKey, pubSign);
        } catch (Exception e) {
            log.error("", e);
        }
        if (status) {
            log.info("签名验证成功");
        } else {
            log.error("签名验证失败");
        }
    }
    public static String sign(Map<String, Object> request, String privateKey) throws Exception {
        log.info("私钥："+privateKey);
        String pubData =JSONObject.toJSONString(request.get("pubData")) ;


        JSONObject jo = JSON.parseObject(pubData);
        pubData = JSON.toJSONString(jo, SerializerFeature.SortField, SerializerFeature.MapSortField, SerializerFeature.WriteMapNullValue,
                SerializerFeature.WriteNullStringAsEmpty, SerializerFeature.WriteNullListAsEmpty);

        String sign = RSATool.sign(pubData, privateKey);
        System.out.println("签名字符串");
        System.out.println(pubData);
        System.out.println("签名结果"+sign);
           return sign;
     }

}
