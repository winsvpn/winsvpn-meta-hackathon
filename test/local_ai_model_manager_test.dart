import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/local_ai_model_manager.dart';

void main() {
  group('LocalAiModelManager Tests', () {
    late Directory tempDir;
    late LocalAiModelManager manager;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('winthos_models_test_');
      manager = LocalAiModelManager(
        customModelDirectories: [tempDir.path],
      );
    });

    tearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test('validates GGUF magic header correctly', () async {
      final validGguf = File('${tempDir.path}/test_model.gguf');
      final bytes = BytesBuilder();
      // 'GGUF' magic: 0x47, 0x47, 0x55, 0x46
      bytes.add([0x47, 0x47, 0x55, 0x46]);
      // Version 3: 0x03, 0x00, 0x00, 0x00
      bytes.add([0x03, 0x00, 0x00, 0x00]);
      // Tensor count (uint64): 100
      bytes.add([100, 0, 0, 0, 0, 0, 0, 0]);
      // Metadata count (uint64): 10
      bytes.add([10, 0, 0, 0, 0, 0, 0, 0]);
      // Pad to > 1024 bytes
      bytes.add(List.filled(2048, 0));
      await validGguf.writeAsBytes(bytes.toBytes());

      final validation = await manager.validateModelFile(validGguf.path);
      expect(validation.isValid, isTrue);
      expect(validation.format, equals(AiModelFormat.gguf));
      expect(validation.version, equals(3));
      expect(validation.tensorCount, equals(100));
    });

    test('rejects truncated file under 16 bytes', () async {
      final corruptFile = File('${tempDir.path}/truncated.gguf');
      await corruptFile.writeAsBytes([0x47, 0x47, 0x00, 0x00]);

      final validation = await manager.validateModelFile(corruptFile.path);
      expect(validation.isValid, isFalse);
      expect(validation.errorMessage, contains('File too small'));
    });

    test('rejects invalid magic header on files >= 16 bytes', () async {
      final invalidFile = File('${tempDir.path}/invalid_magic.gguf');
      await invalidFile.writeAsBytes(List.filled(64, 0x00));

      final validation = await manager.validateModelFile(invalidFile.path);
      expect(validation.isValid, isFalse);
      expect(validation.errorMessage, contains('Invalid GGUF magic header'));
    });

    test('rejects directory traversal attempts', () async {
      final outsideFile = '${tempDir.path}/../secret.txt';
      expect(
        () => manager.sanitizeModelPath(outsideFile),
        throwsA(isA<SecurityException>()),
      );
    });

    test('discovers valid models in configured directory', () async {
      final modelFile = File('${tempDir.path}/superhuman.gguf');
      final bytes = BytesBuilder();
      bytes.add([0x47, 0x47, 0x55, 0x46]); // GGUF
      bytes.add([0x03, 0x00, 0x00, 0x00]); // v3
      bytes.add([50, 0, 0, 0, 0, 0, 0, 0]);
      bytes.add([5, 0, 0, 0, 0, 0, 0, 0]);
      bytes.add(List.filled(2048, 0));
      await modelFile.writeAsBytes(bytes.toBytes());

      final discovered = await manager.discoverModels();
      expect(discovered.length, equals(1));
      expect(discovered.first.fileName, equals('superhuman.gguf'));
      expect(discovered.first.format, equals(AiModelFormat.gguf));
    });
  });
}
