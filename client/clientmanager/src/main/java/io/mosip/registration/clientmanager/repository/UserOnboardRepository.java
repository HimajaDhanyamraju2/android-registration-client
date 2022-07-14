package io.mosip.registration.clientmanager.repository;

import android.util.Log;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import io.mosip.registration.clientmanager.constant.Modality;
import io.mosip.registration.clientmanager.constant.RegistrationConstants;
import io.mosip.registration.clientmanager.dao.UserBiometricDao;
import io.mosip.registration.clientmanager.dao.UserDetailDao;
import io.mosip.registration.clientmanager.dto.registration.BiometricsDto;
import io.mosip.registration.clientmanager.entity.UserBiometric;
import io.mosip.registration.keymanager.util.CryptoUtil;
import io.mosip.registration.packetmanager.cbeffutil.jaxbclasses.BIR;
import io.mosip.registration.packetmanager.dto.PacketWriter.BiometricType;
import io.mosip.registration.packetmanager.util.DateUtils;

public class UserOnboardRepository {

    private static final String TAG = UserOnboardRepository.class.getSimpleName();
    private UserBiometricDao userBiometricDao;
    private UserDetailDao userDetailDao;

    @Inject
    public UserOnboardRepository(UserBiometricDao userBiometricDao, UserDetailDao userDetailDao) {
        this.userBiometricDao = userBiometricDao;
        this.userDetailDao = userDetailDao;
    }

    public String insert(String userId, List<BiometricsDto> biometrics) {
        Log.i(TAG, "Biometric information insertion into table");
        List<UserBiometric> biometricsList = new ArrayList<>();

        try {
            biometrics.forEach(dto -> {
                UserBiometric userBiometric = new UserBiometric();
                String bioAttribute = Modality.getBioAttribute(dto.getBioSubtype());
                userBiometric.setBioAttributeCode(bioAttribute);
                BiometricType bioType = BiometricType.fromValue(Modality.getModality(bioAttribute).getSingleType().value());
                userBiometric.setBioTypeCode(bioType.value());
                userBiometric.setUsrId(userId);
                userBiometric.setBioTemplate(CryptoUtil.base64decoder.decode(dto.getBioValue()));
                userBiometric.setNumberOfRetry(dto.getNumOfRetries());
                Double qualityScore = dto.getQualityScore();
                userBiometric.setQualityScore(qualityScore.intValue());
                userBiometric.setCrBy(userId);
                userBiometric.setCrDtime(Timestamp.valueOf(DateUtils.getUTCCurrentDateTimeString()));
                userBiometric.setIsActive(true);
                biometricsList.add(userBiometric);
            });

            clearUserBiometrics(userId);
            userBiometricDao.insertAllBiometrics(biometricsList);

            Log.i(TAG, "Biometric information insertion successful");
            return RegistrationConstants.SUCCESS;

        } catch (RuntimeException runtimeException) {
            Log.e(TAG, runtimeException.getMessage());
        }
        throw new RuntimeException("USER_ONBOARD_ERROR");
    }

    public String insertExtractedTemplates(List<BIR> templates, String userId) {
        String response;
        List<UserBiometric> biometricsList = new ArrayList<>();

        try {
            templates.forEach( template -> {
                UserBiometric biometrics = new UserBiometric();
                String bioAttribute = Modality.getBioAttribute(template.getBdbInfo().getSubtype());
                biometrics.setBioAttributeCode(bioAttribute);
                BiometricType bioType = BiometricType.fromValue(Modality.getModality(bioAttribute).getSingleType().value());
                biometrics.setBioTypeCode(bioType.value());
                biometrics.setUsrId(userId);
                biometrics.setBioTemplate(template.getBdb());
                Long qualityScore = template.getBdbInfo().getQuality().getScore();
                biometrics.setQualityScore(qualityScore.intValue());
                biometrics.setCrBy(userId);
                biometrics.setCrDtime(Timestamp.valueOf(DateUtils.getUTCCurrentDateTimeString()));
                biometrics.setIsActive(true);
                biometricsList.add(biometrics);
            });

            clearUserBiometrics(userId);
            userBiometricDao.insertAllBiometrics(biometricsList);

            response = RegistrationConstants.SUCCESS;
        } catch (RuntimeException runtimeException) {
            throw new RuntimeException("USER_ONBOARD_ERROR");
        }
        return response;
    }

    private void clearUserBiometrics(String userId) {
        userBiometricDao.deleteByUsrId(userId);
    }
}
