package io.mosip.registration.clientmanager.spi;

import java.util.List;

import io.mosip.registration.clientmanager.dto.registration.BiometricsDto;
import io.mosip.registration.clientmanager.exception.ClientCheckedException;

public interface UserOnboardService {
    boolean validateWithIDAuthAndSave(List<BiometricsDto> biometrics) throws ClientCheckedException;
}
