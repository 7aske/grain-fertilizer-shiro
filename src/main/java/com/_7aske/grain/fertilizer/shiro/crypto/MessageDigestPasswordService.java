package com._7aske.grain.fertilizer.shiro.crypto;

import net.bytebuddy.agent.builder.AgentBuilder;
import org.apache.shiro.authc.credential.PasswordService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MessageDigestPasswordService implements PasswordService {
    private final MessageDigest digest;

    public MessageDigestPasswordService() throws NoSuchAlgorithmException {
        digest = MessageDigest.getInstance("SHA-256");
    }

    @Override
    public String encryptPassword(Object plaintextPassword) throws IllegalArgumentException {
        if (plaintextPassword instanceof String str) {
            plaintextPassword = str.toCharArray();
        }

        byte[] encodedHash = digest.digest(new String((char[]) plaintextPassword).getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(encodedHash));
    }

    @Override
    public boolean passwordsMatch(Object submittedPlaintext, String encrypted) {
        return encrypted.equals(encryptPassword(submittedPlaintext));
    }
}
