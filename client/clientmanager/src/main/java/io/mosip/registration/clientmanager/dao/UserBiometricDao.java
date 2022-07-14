package io.mosip.registration.clientmanager.dao;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

import java.util.List;

import io.mosip.registration.clientmanager.entity.UserBiometric;

@Dao
public interface UserBiometricDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertAllBiometrics(List<UserBiometric> biometrics);

    @Query("select * from user_biometric where usr_id=:userId")
    List<UserBiometric> findByUsrId(String userId);

    @Query("delete from user_biometric where usr_id=:userID")
    void deleteByUsrId(String userID);

}
