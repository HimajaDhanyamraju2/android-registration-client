import 'package:pigeon/pigeon.dart';

@HostApi()
abstract class BiometricsApi {
  @async
  String invokeDiscoverSbi(String fieldId,String modality);

  @async
  List<String> getBestBiometrics(String fieldId, String modality);

  @async
  List<Uint8List> extractImageValues();


}
