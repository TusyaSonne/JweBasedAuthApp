package ru.dzhenbaz.JweBasedAuthApp.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

@Service
@RequiredArgsConstructor
public class JweTokenService {
    private final KeyPair keyPair;

    public String generateToken(String subject) throws JOSEException {
        Payload payload = new Payload("{\"sub\":\"" + subject + "\"}");

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("JWT")
                .build();

        JWEObject jweObject = new JWEObject(header, payload);
        RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) keyPair.getPublic());
        jweObject.encrypt(encrypter);

        return jweObject.serialize();
    }

    public String decryptToken(String token) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(token);
        RSADecrypter decrypter = new RSADecrypter( keyPair.getPrivate());
        jweObject.decrypt(decrypter);

        return jweObject.getPayload().toString();
    }
}
