package io.mosip.registration.clientmanager.constant;

import java.util.Arrays;
import java.util.List;

public class RegistrationConstants {

    public static final String COMMA = ",";
    public static final String EMPTY_STRING = "";
    public static final String AGE_GROUP = "ageGroup";
    public static final String AGE = "age";
    public static final String DEFAULT_AGE_GROUP = "adult";
    public static final String PROCESS_KEY = "_process";
    public static final String FLOW_KEY = "_flow";
    public static final String ID_SCHEMA_VERSION = "IDSchemaVersion";
    public static final List<String> RIGHT_SLAB_ATTR = Arrays.asList("rightIndex","rightMiddle","rightRing","rightLittle");
    public static final List<String> LEFT_SLAB_ATTR = Arrays.asList("leftIndex","leftMiddle","leftRing","leftLittle");
    public static final List<String> THUMBS_ATTR = Arrays.asList("leftThumb", "rightThumb");
    public static final List<String> DOUBLE_IRIS_ATTR = Arrays.asList("leftEye", "rightEye");
    public static final List<String> FACE_ATTR = Arrays.asList("");
    public static final List<String> EXCEPTION_PHOTO_ATTR = Arrays.asList("unknown");


    //SBI intents
    public static final String DISCOVERY_INTENT_ACTION = "io.sbi.device";
    public static final String D_INFO_INTENT_ACTION = ".Info";
    public static final String R_CAPTURE_INTENT_ACTION = ".rCapture";
    public static final String SBI_INTENT_REQUEST_KEY = "input";
    public static final String SBI_INTENT_RESPONSE_KEY = "response";

    //Global param keys
    public static final String MANDATORY_LANGUAGES_KEY = "mosip.mandatory-languages";
    public static final String OPTIONAL_LANGUAGES_KEY = "mosip.optional-languages";
    public static final String MAX_LANGUAGES_COUNT_KEY = "mosip.max-languages.count";
    public static final String MIN_LANGUAGES_COUNT_KEY = "mosip.min-languages.count";

    //Audits
    public static final String REGISTRATION_SCREEN = "Registration: %s";

    public static final String ON_BOARD_TIME_STAMP = "timestamp";
    public static final String ON_BOARD_BIO_TYPE = "bioType";
    public static final String ON_BOARD_BIO_SUB_TYPE = "bioSubType";
    public static final String ON_BOARD_BIO_VALUE = "bioValue";
    public static final String ON_BOARD_BIO_DATA = "data";
    public static final String ON_BOARD_BIOMETRICS = "biometrics";
    public static final String ON_BOARD_REQUEST = "request";
    public static final String ON_BOARD_REQUEST_HMAC = "requestHMAC";
    public static final String ON_BOARD_REQUEST_SESSION_KEY = "requestSessionKey";

    public static final String APP_ID_IDA = "IDA";
    public static final String IDA_REFERENCE_ID = "INTERNAL";
    public static final String PUBLIC_KEY_IDA_REST = "ida_key";
    public static final String ON_BOARD_IDA_VALIDATION = "ida_auth";
    public static final String ID = "id";
    public static final String IDENTITY = "mosip.identity.auth.internal";
    public static final String VERSION = "version";
    public static final String ENV = "env";
    public static final String DOMAIN_URI = "domainUri";
    public static final String TRANSACTION_Id = "transactionId";
    public static final String PURPOSE = "purpose";
    public static final String PURPOSE_AUTH = "Auth";
    public static final String REQUEST_TIME = "requestTime";
    public static final String TRANSACTION_ID = "transactionID";
    public static final String TRANSACTION_ID_VALUE = "1234567890";
    public static final String AUTH_HASH = "hash";
    public static final String SESSION_KEY = "sessionKey";
    public static final String SIGNATURE = "signature";
    public static final String RESPONSE = "response";
    public static final String JOB_TRIGGER_POINT_SYSTEM = "System";
    public static final String JOB_TRIGGER_POINT_USER = "User";
    public static final String CONSENT_OBTAINED = "consentObtained";
    public static final String INDIVIDUAL_ID = "individualId";
    public static final String INDIVIDUAL_ID_TYPE = "individualIdType";
    public static final String KEY_INDEX = "keyIndex";
    public static final String USER_ID_CODE = "USERID";
    public static final String BIO = "bio";
    public static final String REQUEST_AUTH = "requestedAuth";
    public static final String TIME_STAMP = "timeStamp";
    public static final String REF_ID = "referenceId";
    public static final String THUMBPRINT = "thumbprint";
    public static final String ON_BOARD_AUTH_STATUS = "authStatus";

    public static final String FINGERPRINT_UPPERCASE = "FINGERPRINT";
    public static final String FACE = "FACE";
    public static final String IRIS = "IRIS";
    public static final String SUCCESS = "Success";
    public static final String ERRORS = "errors";
}
