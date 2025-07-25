package ru.dzhenbaz.JweBasedAuthApp.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.dzhenbaz.JweBasedAuthApp.model.dto.TokenPayload;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

@Service
@RequiredArgsConstructor
public class JweTokenService {
    private final KeyPair keyPair;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String generateToken(String subject) throws JsonProcessingException, JOSEException {
        TokenPayload tokenPayload = new TokenPayload(subject);
        String jsonPayload = objectMapper.writeValueAsString(tokenPayload);

        Payload payload = new Payload(jsonPayload);

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
