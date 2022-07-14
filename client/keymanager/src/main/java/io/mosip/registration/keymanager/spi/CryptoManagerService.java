package io.mosip.registration.keymanager.spi;

import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;

import io.mosip.registration.keymanager.dto.CryptoManagerRequestDto;
import io.mosip.registration.keymanager.dto.CryptoManagerResponseDto;

public interface CryptoManagerService {

    CryptoManagerResponseDto encrypt(CryptoManagerRequestDto cryptoRequestDto) throws Exception;

    byte[] symmetricEncrypt(SecretKey secretKey, byte[] data, byte[] iv, byte[] aad) throws Exception;

    byte[] symmetricEncrypt(SecretKey secretKey, byte[] data, byte[] aad) throws Exception;

    byte[] asymmetricEncrypt(PublicKey publicKey, byte[] data) throws Exception;

    Certificate convertToCertificate(String certData) throws Exception;

    byte[] getCertificateThumbprint(Certificate cert) throws Exception;

}
