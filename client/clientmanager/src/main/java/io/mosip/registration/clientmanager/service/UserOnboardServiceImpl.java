package io.mosip.registration.clientmanager.service;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.IntStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.inject.Inject;
import javax.inject.Singleton;

import io.mosip.registration.clientmanager.R;
import io.mosip.registration.clientmanager.config.SessionManager;
import io.mosip.registration.clientmanager.constant.Modality;
import io.mosip.registration.clientmanager.constant.RegistrationConstants;
import io.mosip.registration.clientmanager.dto.http.ResponseWrapper;
import io.mosip.registration.clientmanager.dto.http.ServiceError;
import io.mosip.registration.clientmanager.dto.registration.BiometricsDto;
import io.mosip.registration.clientmanager.exception.ClientCheckedException;
import io.mosip.registration.clientmanager.repository.UserDetailRepository;
import io.mosip.registration.clientmanager.repository.UserOnboardRepository;
import io.mosip.registration.clientmanager.spi.RegistrationService;
import io.mosip.registration.clientmanager.spi.SyncRestService;
import io.mosip.registration.clientmanager.spi.UserOnboardService;
import io.mosip.registration.clientmanager.util.SyncRestUtil;
import io.mosip.registration.keymanager.dto.CryptoManagerRequestDto;
import io.mosip.registration.keymanager.dto.CryptoManagerResponseDto;
import io.mosip.registration.keymanager.exception.KeymanagerServiceException;
import io.mosip.registration.keymanager.spi.CryptoManagerService;
import io.mosip.registration.packetmanager.cbeffutil.jaxbclasses.SingleAnySubtypeType;
import io.mosip.registration.packetmanager.dto.PacketWriter.BiometricType;
import io.mosip.registration.packetmanager.util.CryptoUtil;
import io.mosip.registration.packetmanager.util.DateUtils;
import io.mosip.registration.packetmanager.util.HMACUtils2;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

@Singleton
public class UserOnboardServiceImpl implements UserOnboardService {

    private static final String TAG = UserOnboardServiceImpl.class.getSimpleName();
    private Context context;
    private SyncRestService syncRestService;
    private RegistrationService registrationService;
    private CryptoManagerService cryptoManagerService;
    private UserOnboardRepository userOnboardRepository;
    private UserDetailRepository userDetailRepository;
    private String certificateData;
    private Map<String, Object> onBoardResponseMap;

    @Inject
    public UserOnboardServiceImpl(Context context, SyncRestService syncRestService, RegistrationService registrationService, CryptoManagerService cryptoManagerService,
                                  UserOnboardRepository userOnboardRepository, UserDetailRepository userDetailRepository) {
        this.context = context;
        this.syncRestService = syncRestService;
        this.registrationService = registrationService;
        this.cryptoManagerService = cryptoManagerService;
        this.userOnboardRepository = userOnboardRepository;
        this.userDetailRepository = userDetailRepository;
    }

    @Override
    public boolean validateWithIDAuthAndSave(List<BiometricsDto> biometrics) throws ClientCheckedException {
        if (Objects.isNull(biometrics))
            throw new ClientCheckedException(context, R.string.err_009);
        if (validateWithIDA(getUserID(), biometrics)) {
            return save(biometrics);
        }
        return false;
    }

    private boolean validateWithIDA(String userId, List<BiometricsDto> biometrics) {
        Map<String, Object> idaRequestMap = new LinkedHashMap<>();
        idaRequestMap.put(RegistrationConstants.ID, RegistrationConstants.IDENTITY);
        idaRequestMap.put(RegistrationConstants.VERSION, "1.0");
        idaRequestMap.put(RegistrationConstants.REQUEST_TIME,
                DateUtils.formatToISOString(DateUtils.getUTCCurrentDateTime()));
        idaRequestMap.put(RegistrationConstants.ENV, "dev.mosip.net");
        idaRequestMap.put(RegistrationConstants.DOMAIN_URI, "https://dev.mosip.net");
        idaRequestMap.put(RegistrationConstants.TRANSACTION_ID, RegistrationConstants.TRANSACTION_ID_VALUE);
        idaRequestMap.put(RegistrationConstants.CONSENT_OBTAINED, true);
        idaRequestMap.put(RegistrationConstants.INDIVIDUAL_ID, userId);
        idaRequestMap.put(RegistrationConstants.INDIVIDUAL_ID_TYPE, RegistrationConstants.USER_ID_CODE);
        idaRequestMap.put(RegistrationConstants.KEY_INDEX, "");

        Map<String, Boolean> tempMap = new HashMap<>();
        tempMap.put(RegistrationConstants.BIO, true);
        idaRequestMap.put(RegistrationConstants.REQUEST_AUTH, tempMap);

        List<Map<String, Object>> listOfBiometric = new ArrayList<>();
        Map<String, Object> requestMap = new LinkedHashMap<>();

        Map<String, String> requestParamMap = new LinkedHashMap<>();
        requestParamMap.put(RegistrationConstants.REF_ID, RegistrationConstants.IDA_REFERENCE_ID);
        requestParamMap.put(RegistrationConstants.TIME_STAMP,
                DateUtils.formatToISOString(DateUtils.getUTCCurrentDateTime()));

        try {
            getCertificate(requestParamMap);
            if (certificateData == null) {
                Log.e(TAG, "Public key is either null or invalid public key");
                return false;
            }
            //TODO method call need to be updated
            Certificate certificate = keymanagerUtil.convertToCertificate(certificateData);

            if (Objects.nonNull(biometrics) && !biometrics.isEmpty()) {
                String previousHash = HMACUtils2.digestAsPlainText("".getBytes());

                for (BiometricsDto dto : biometrics) {
                    BiometricType bioType = BiometricType.fromValue(Modality.getModality(Modality.getBioAttribute(dto.getBioSubType())).getSingleType().value());
                    String bioSubType = getSubTypesAsString(bioType, Modality.getBioAttribute(dto.getBioSubType()));
                    LinkedHashMap<String, Object> dataBlock = buildDataBlock(bioType.name(), bioSubType,
                            io.mosip.registration.keymanager.util.CryptoUtil.base64decoder.decode(dto.getBioValue()), previousHash, dto);
                    dataBlock.put(RegistrationConstants.THUMBPRINT, CryptoUtil.encodeToURLSafeBase64(cryptoManagerService.getCertificateThumbprint(certificate)));
                    previousHash = (String) dataBlock.get(RegistrationConstants.AUTH_HASH);
                    listOfBiometric.add(dataBlock);
                }
            }

            if (listOfBiometric.isEmpty())
                throw new ClientCheckedException(context, R.string.err_009);

            requestMap.put(RegistrationConstants.ON_BOARD_BIOMETRICS, listOfBiometric);
            requestMap.put(RegistrationConstants.ON_BOARD_TIME_STAMP,
                    DateUtils.formatToISOString(DateUtils.getUTCCurrentDateTime()));

            getIdaAuthResponse(idaRequestMap, requestMap, requestParamMap, certificate);
            return userOnBoardStatusFlag(userId);
        } catch (Exception e) {
            Log.e(TAG, e.getMessage(), e);
        }
        return false;
    }

    private void getCertificate(Map<String, String> requestParamMap) throws Exception {
        try {
            //TODO method call need to be updated
            KeyPairGenerateResponseDto certificateDto = keymanagerService.getCertificate("IDA",
                    Optional.of("INTERNAL"));

            if (certificateDto != null && certificateDto.getCertificate() != null)
                return certificateDto.getCertificate();
        } catch (KeymanagerServiceException ex) {
            Log.e(TAG, "No entry found for applicationId : IDA", ex);
        }

        Call<ResponseWrapper<Map<String, Object>>> call = syncRestService.getIDACertificate(requestParamMap.get(RegistrationConstants.REF_ID),
                requestParamMap);

        call.enqueue(new Callback<ResponseWrapper<Map<String, Object>>>() {
            @Override
            public void onResponse(Call<ResponseWrapper<Map<String, Object>>> call, Response<ResponseWrapper<Map<String, Object>>> response) {
                if (response.isSuccessful()) {
                    ServiceError error = SyncRestUtil.getServiceError(response.body());
                    if (error == null) {
                        LinkedHashMap<String, Object> responseMap = response.body().getResponse();
                        certificateData = responseMap.get("certificate").toString();

                        //TODO Class and method call need to be updated
                        UploadCertificateRequestDto uploadCertificateRequestDto = new UploadCertificateRequestDto();
                        uploadCertificateRequestDto.setApplicationId("IDA");
                        uploadCertificateRequestDto.setReferenceId("INTERNAL");
                        uploadCertificateRequestDto.setCertificateData(certificateData);
                        keymanagerService.uploadOtherDomainCertificate(uploadCertificateRequestDto);

                        Toast.makeText(context, context.getString(R.string.get_certificate_completed), Toast.LENGTH_LONG).show();
                    } else
                        Toast.makeText(context, String.format("%s %s", context.getString(R.string.get_certificate_failed), error.getMessage()), Toast.LENGTH_LONG).show();
                } else
                    Toast.makeText(context, String.format("%s. %s:%s", context.getString(R.string.get_certificate_failed), context.getString(R.string.status_code), String.valueOf(response.code())), Toast.LENGTH_LONG).show();
            }

            @Override
            public void onFailure(Call<ResponseWrapper<Map<String, Object>>> call, Throwable t) {
                Toast.makeText(context, context.getString(R.string.get_certificate_failed), Toast.LENGTH_LONG).show();
            }
        });
    }

    private LinkedHashMap<String, Object> buildDataBlock(String bioType, String bioSubType, byte[] attributeISO,
                                                         String previousHash, BiometricsDto biometricsDto) throws Exception {
        Log.i(TAG, "Building data block for User Onboard Authentication with IDA");

        LinkedHashMap<String, Object> dataBlock = new LinkedHashMap<>();
        Map<String, Object> data = new HashMap<>();
        data.put(RegistrationConstants.ON_BOARD_TIME_STAMP,
                DateUtils.formatToISOString(DateUtils.getUTCCurrentDateTime()));
        data.put(RegistrationConstants.ON_BOARD_BIO_TYPE, bioType);
        data.put(RegistrationConstants.ON_BOARD_BIO_SUB_TYPE, bioSubType);
        SplitEncryptedData responseMap = getSessionKey(data, attributeISO);
        data.put(RegistrationConstants.ON_BOARD_BIO_VALUE, responseMap.getEncryptedData());
        data.put(RegistrationConstants.TRANSACTION_Id, RegistrationConstants.TRANSACTION_ID_VALUE);
        data.put(RegistrationConstants.PURPOSE, RegistrationConstants.PURPOSE_AUTH);
        data.put(RegistrationConstants.ENV, "dev.mosip.net");
        data.put(RegistrationConstants.DOMAIN_URI, "https://dev.mosip.net");
        String dataBlockJsonString = RegistrationConstants.EMPTY_STRING;
        try {
            dataBlockJsonString = new ObjectMapper().writeValueAsString(data);
            dataBlock.put(RegistrationConstants.ON_BOARD_BIO_DATA,
                    CryptoUtil.encodeToURLSafeBase64(dataBlockJsonString.getBytes()));
        } catch (IOException ex) {
            Log.e(TAG, ex.getMessage(), ex);
        }

        String presentHash = HMACUtils2.digestAsPlainText(dataBlockJsonString.getBytes());
        String concatenatedHash = previousHash + presentHash;
        String finalHash = HMACUtils2.digestAsPlainText(concatenatedHash.getBytes());

        dataBlock.put(RegistrationConstants.AUTH_HASH, finalHash);
        dataBlock.put(RegistrationConstants.SESSION_KEY, responseMap.getEncryptedSessionKey());

        Log.i(TAG, "Returning the dataBlock for User Onboard Authentication with IDA");
        return dataBlock;
    }

    private synchronized SplitEncryptedData getSessionKey(Map<String, Object> requestMap, byte[] data) throws Exception {
        Log.i(TAG, "Getting sessionKey for User Onboard Authentication with IDA");

        String timestamp = (String) requestMap.get(RegistrationConstants.ON_BOARD_TIME_STAMP);
        byte[] xorBytes = getXOR(timestamp, RegistrationConstants.TRANSACTION_ID_VALUE);
        byte[] saltLastBytes = getLastBytes(xorBytes, 12);
        byte[] aadLastBytes = getLastBytes(xorBytes, 16);

        CryptoManagerRequestDto cryptomanagerRequestDto = new CryptoManagerRequestDto();
        cryptomanagerRequestDto.setAad(CryptoUtil.encodeToURLSafeBase64(aadLastBytes));
        cryptomanagerRequestDto.setApplicationId(RegistrationConstants.APP_ID_IDA);
        cryptomanagerRequestDto.setData(CryptoUtil.encodeToURLSafeBase64(data));
        cryptomanagerRequestDto.setReferenceId(RegistrationConstants.IDA_REFERENCE_ID);
        cryptomanagerRequestDto.setSalt(CryptoUtil.encodeToURLSafeBase64(saltLastBytes));
        cryptomanagerRequestDto.setTimeStamp(DateUtils.getUTCCurrentDateTime());
        CryptoManagerResponseDto cryptomanagerResponseDto = cryptoManagerService.encrypt(cryptomanagerRequestDto);

        Log.i(TAG, "Returning the sessionKey for User Onboard Authentication with IDA");
        return splitEncryptedData(cryptomanagerResponseDto.getData());
    }

    private String getSubTypesAsString(BiometricType bioType, String bioAttribute) {
        List<String> subtypes = new LinkedList<>();
        switch (bioType) {
            case FINGER:
                subtypes.add(bioAttribute.contains("left") ? SingleAnySubtypeType.LEFT.value()
                        : SingleAnySubtypeType.RIGHT.value());
                if (bioAttribute.toLowerCase().contains("thumb"))
                    subtypes.add(SingleAnySubtypeType.THUMB.value());
                else {
                    String val = bioAttribute.toLowerCase().replace("left", "").replace("right", "");
                    subtypes.add(SingleAnySubtypeType.fromValue(StringUtils.capitalize(val).concat("Finger"))
                            .value());
                }
                break;
            case IRIS:
                subtypes.add(bioAttribute.contains("left") ? SingleAnySubtypeType.LEFT.value()
                        : SingleAnySubtypeType.RIGHT.value());
                break;
            default:
                break;
        }
        return String.join(" ", subtypes);
    }

    private Boolean userOnBoardStatusFlag(String userId) {
        Boolean userOnboardFlag = false;
        if (null != onBoardResponseMap && null != onBoardResponseMap.get(RegistrationConstants.RESPONSE)
                && null == onBoardResponseMap.get(RegistrationConstants.ERRORS)) {
            LinkedHashMap<String, Object> responseMap = (LinkedHashMap<String, Object>) onBoardResponseMap
                    .get(RegistrationConstants.RESPONSE);
            Log.i(TAG, "authStatus true");
            userOnboardFlag = (Boolean) responseMap.get(RegistrationConstants.ON_BOARD_AUTH_STATUS);
        } else if (null != onBoardResponseMap && null != onBoardResponseMap.get(RegistrationConstants.ERRORS)) {
            List<LinkedHashMap<String, Object>> listOfFailureResponse = (List<LinkedHashMap<String, Object>>) onBoardResponseMap
                    .get(RegistrationConstants.ERRORS);
            LinkedHashMap<String, Object> responseMap = (LinkedHashMap<String, Object>) onBoardResponseMap
                    .get(RegistrationConstants.RESPONSE);
            userOnboardFlag = (Boolean) responseMap.get(RegistrationConstants.ON_BOARD_AUTH_STATUS);
            Log.e(TAG, listOfFailureResponse.toString());
        }
        return userOnboardFlag;
    }

    private void getIdaAuthResponse(Map<String, Object> idaRequestMap, Map<String, Object> requestMap,
                                    Map<String, String> requestParamMap, Certificate certificate) {
        try {
            PublicKey publicKey = certificate.getPublicKey();
            idaRequestMap.put(RegistrationConstants.THUMBPRINT, CryptoUtil.encodeToURLSafeBase64(cryptoManagerService.getCertificateThumbprint(certificate)));

            Log.i(TAG, "Getting Symmetric Key.....");
            // Symmetric key alias session key
            //TODO method call need to be updated
            KeyGenerator keyGenerator = KeyGeneratorUtils.getKeyGenerator("AES", 256);
            // Generate AES Session Key
            final SecretKey symmetricKey = keyGenerator.generateKey();

            Log.i(TAG, "Preparing request.....");
            // request
            idaRequestMap.put(RegistrationConstants.ON_BOARD_REQUEST,
                    CryptoUtil.encodeToURLSafeBase64(cryptoManagerService.symmetricEncrypt(symmetricKey,
                            new ObjectMapper().writeValueAsString(requestMap).getBytes(), null)));

            Log.i(TAG, "preparing request HMAC.....");
            // requestHMAC
            idaRequestMap.put(RegistrationConstants.ON_BOARD_REQUEST_HMAC,
                    CryptoUtil.encodeToURLSafeBase64(cryptoManagerService.symmetricEncrypt(symmetricKey, HMACUtils2
                                    .digestAsPlainText(new ObjectMapper().writeValueAsString(requestMap).getBytes()).getBytes(),
                            null)));

            Log.i(TAG, "preparing request Session Key.....");
            // requestSession Key
            idaRequestMap.put(RegistrationConstants.ON_BOARD_REQUEST_SESSION_KEY,
                    CryptoUtil.encodeToURLSafeBase64(cryptoManagerService.asymmetricEncrypt(publicKey, symmetricKey.getEncoded())));

            Log.i(TAG, "Ida Auth rest calling.....");

            Call<ResponseWrapper<Map<String, Object>>> call = syncRestService.onboardAuth(idaRequestMap);
            call.enqueue(new Callback<ResponseWrapper<Map<String, Object>>>() {
                @Override
                public void onResponse(Call<ResponseWrapper<Map<String, Object>>> call, Response<ResponseWrapper<Map<String, Object>>> response) {
                    if (response.isSuccessful()) {
                        ServiceError error = SyncRestUtil.getServiceError(response.body());
                        if (error == null) {
                            onBoardResponseMap = response.body().getResponse();
                            Toast.makeText(context, context.getString(R.string.ida_auth_completed), Toast.LENGTH_LONG).show();
                        } else
                            Toast.makeText(context, String.format("%s %s", context.getString(R.string.ida_auth_failed), error.getMessage()), Toast.LENGTH_LONG).show();
                    } else
                        Toast.makeText(context, String.format("%s. %s:%s", context.getString(R.string.ida_auth_failed), context.getString(R.string.status_code), String.valueOf(response.code())), Toast.LENGTH_LONG).show();
                }

                @Override
                public void onFailure(Call<ResponseWrapper<Map<String, Object>>> call, Throwable t) {
                    Toast.makeText(context, context.getString(R.string.ida_auth_failed), Toast.LENGTH_LONG).show();
                }
            });
        } catch (Exception ex) {
            Log.e(TAG, ex.getMessage());
        }
    }

    private boolean save(List<BiometricsDto> biometrics) {
        Log.i(TAG, "Entering save method");
        try {
            String onboardResponse = userOnboardRepository.insert(getUserID(), biometrics);
            if (onboardResponse.equalsIgnoreCase(RegistrationConstants.SUCCESS)) {
                Log.i(TAG, "Operator details inserted");
                userDetailRepository.updateUserDetail(getUserID(),true);
                Log.i(TAG, "UserDetail table updated with onboard status");
                return true;
            }
        } catch (Exception exception) {
            Log.e(TAG, exception.getMessage());
        }
        return false;
    }

    public String getUserID() {
        return this.context.getSharedPreferences(this.context.getString(R.string.app_name),
                Context.MODE_PRIVATE).getString(SessionManager.USER_NAME, null);
    }

    /**
     * Method to insert specified number of 0s in the beginning of the given string
     *
     * @param string
     * @param count  - number of 0's to be inserted
     * @return bytes
     */
    private byte[] prependZeros(byte[] string, int count) {
        byte[] newBytes = new byte[string.length + count];
        int i = 0;
        for (; i < count; i++) {
            newBytes[i] = 0;
        }
        for (int j = 0; i < newBytes.length; i++, j++) {
            newBytes[i] = string[j];
        }
        return newBytes;
    }

    /**
     * Method to return the XOR of the given strings
     */
    private byte[] getXOR(String timestamp, String transactionId) {
        Log.i(TAG, "Started getting XOR of timestamp and transactionId");

        byte[] timestampBytes = timestamp.getBytes();
        byte[] transactionIdBytes = transactionId.getBytes();
        // Lengths of the given strings
        int timestampLength = timestampBytes.length;
        int transactionIdLength = transactionIdBytes.length;

        // Make both the strings of equal lengths
        // by inserting 0s in the beginning
        if (timestampLength > transactionIdLength) {
            transactionIdBytes = prependZeros(transactionIdBytes, timestampLength - transactionIdLength);
        } else if (transactionIdLength > timestampLength) {
            timestampBytes = prependZeros(timestampBytes, transactionIdLength - timestampLength);
        }

        // Updated length
        int length = Math.max(timestampLength, transactionIdLength);
        byte[] xorBytes = new byte[length];

        // To store the resultant XOR
        for (int i = 0; i < length; i++) {
            xorBytes[i] = (byte) (timestampBytes[i] ^ transactionIdBytes[i]);
        }

        Log.i(TAG, "Returning XOR of timestamp and transactionId");
        return xorBytes;
    }

    /**
     * Gets the last bytes.
     *
     * @param xorBytes
     * @param lastBytesNum the last bytes num
     * @return the last bytes
     */
    private byte[] getLastBytes(byte[] xorBytes, int lastBytesNum) {
        assert (xorBytes.length >= lastBytesNum);
        return Arrays.copyOfRange(xorBytes, xorBytes.length - lastBytesNum, xorBytes.length);
    }

    /**
     * Split encrypted data.
     *
     * @param data the data
     * @return the splitted encrypted data
     */
    public SplitEncryptedData splitEncryptedData(String data) {
        byte[] dataBytes = CryptoUtil.decodeURLSafeBase64(data);
        byte[][] splits = splitAtFirstOccurrence(dataBytes, (String.valueOf("#KEY_SPLITTER#")).getBytes());
        return new SplitEncryptedData(CryptoUtil.encodeToURLSafeBase64(splits[0]), CryptoUtil.encodeToURLSafeBase64(splits[1]));
    }

    /**
     * Split at first occurance.
     *
     * @param strBytes the str bytes
     * @param sepBytes the sep bytes
     * @return the byte[][]
     */
    private static byte[][] splitAtFirstOccurrence(byte[] strBytes, byte[] sepBytes) {
        int index = findIndex(strBytes, sepBytes);
        if (index >= 0) {
            byte[] bytes1 = new byte[index];
            byte[] bytes2 = new byte[strBytes.length - (bytes1.length + sepBytes.length)];
            System.arraycopy(strBytes, 0, bytes1, 0, bytes1.length);
            System.arraycopy(strBytes, (bytes1.length + sepBytes.length), bytes2, 0, bytes2.length);
            return new byte[][]{bytes1, bytes2};
        } else {
            return new byte[][]{strBytes, new byte[0]};
        }
    }

    /**
     * Find index.
     *
     * @param arr    the arr
     * @param subarr the subarr
     * @return the int
     */
    private static int findIndex(byte arr[], byte[] subarr) {
        int len = arr.length;
        int subArrayLen = subarr.length;
        return IntStream.range(0, len).filter(currentIndex -> {
            if ((currentIndex + subArrayLen) <= len) {
                byte[] sArray = new byte[subArrayLen];
                System.arraycopy(arr, currentIndex, sArray, 0, subArrayLen);
                return Arrays.equals(sArray, subarr);
            }
            return false;
        }).findFirst() // first occurence
                .orElse(-1); // No element found
    }

    /**
     * The Class SplitEncryptedData.
     */
    public static class SplitEncryptedData {
        private String encryptedSessionKey;
        private String encryptedData;

        public SplitEncryptedData() {
            super();
        }

        public SplitEncryptedData(String encryptedSessionKey, String encryptedData) {
            super();
            this.encryptedData = encryptedData;
            this.encryptedSessionKey = encryptedSessionKey;
        }

        public String getEncryptedData() {
            return encryptedData;
        }

        public void setEncryptedData(String encryptedData) {
            this.encryptedData = encryptedData;
        }

        public String getEncryptedSessionKey() {
            return encryptedSessionKey;
        }

        public void setEncryptedSessionKey(String encryptedSessionKey) {
            this.encryptedSessionKey = encryptedSessionKey;
        }

    }

}
