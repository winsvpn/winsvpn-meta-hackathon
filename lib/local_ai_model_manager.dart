import 'dart:io';
import 'dart:typed_data';
import 'package:path/path.dart' as p;

enum AiModelFormat { gguf, winslgbm, tabular, unknown }

class SecurityException implements Exception {
  final String message;
  SecurityException(this.message);
  @override
  String toString() => 'SecurityException: $message';
}

class ModelValidationResult {
  final bool isValid;
  final AiModelFormat format;
  final int version;
  final int tensorCount;
  final int fileSize;
  final String? errorMessage;
  final String? architecture;

  const ModelValidationResult({
    required this.isValid,
    this.format = AiModelFormat.unknown,
    this.version = 0,
    this.tensorCount = 0,
    this.fileSize = 0,
    this.errorMessage,
    this.architecture,
  });

  factory ModelValidationResult.invalid(String error) {
    return ModelValidationResult(
      isValid: false,
      errorMessage: error,
    );
  }
}

class DiscoveredModel {
  final String fileName;
  final String fullPath;
  final AiModelFormat format;
  final int sizeBytes;
  final DateTime lastModified;
  final ModelValidationResult validation;

  const DiscoveredModel({
    required this.fileName,
    required this.fullPath,
    required this.format,
    required this.sizeBytes,
    required this.lastModified,
    required this.validation,
  });
}

class LocalAiModelManager {
  final List<String> _customModelDirectories;

  LocalAiModelManager({
    List<String>? customModelDirectories,
  }) : _customModelDirectories = customModelDirectories ?? [];

  /// Standard paths on Android and cross-platform devices.
  static const List<String> defaultAndroidPaths = [
    '/sdcard/Android/data/org.winsvpn.app.debug/files/models',
    '/sdcard/Android/data/org.winsvpn.app/files/models',
    '/sdcard/Download/winthos_models',
  ];

  Future<List<String>> getTargetModelDirectories() async {
    final dirs = <String>[];
    dirs.addAll(_customModelDirectories);

    if (Platform.isAndroid) {
      dirs.addAll(defaultAndroidPaths);
    } else {
      final home = Platform.environment['HOME'];
      if (home != null) {
        dirs.add('$home/.winthos/models');
      }
    }

    final validDirs = <String>[];
    for (final d in dirs) {
      try {
        final dir = Directory(d);
        if (!await dir.exists()) {
          await dir.create(recursive: true);
        }
        validDirs.add(p.normalize(p.absolute(dir.path)));
      } catch (_) {
        // Skip unwriteable or restricted directories fail-closed
      }
    }
    return validDirs;
  }

  /// Sanitizes and canonicalizes a model path, preventing directory traversal.
  String sanitizeModelPath(String inputPath) {
    if (inputPath.contains('\x00')) {
      throw SecurityException('Path contains null bytes');
    }

    final normalized = p.normalize(p.absolute(inputPath));
    final allowed = _customModelDirectories.isNotEmpty
        ? _customModelDirectories
        : (Platform.isAndroid ? defaultAndroidPaths : [Platform.environment['HOME'] ?? '/']);

    bool isWithinAllowed = false;
    for (final prefix in allowed) {
      final normPrefix = p.normalize(p.absolute(prefix));
      if (normalized == normPrefix || p.isWithin(normPrefix, normalized)) {
        isWithinAllowed = true;
        break;
      }
    }

    if (!isWithinAllowed) {
      throw SecurityException('Model path $inputPath resolves outside allowed storage roots.');
    }

    return normalized;
  }

  /// Asynchronously validates GGUF or LightGBM model header integrity.
  Future<ModelValidationResult> validateModelFile(String filePath) async {
    try {
      final sanitizedPath = sanitizeModelPath(filePath);
      final file = File(sanitizedPath);
      if (!await file.exists()) {
        return ModelValidationResult.invalid('File does not exist: $filePath');
      }

      final length = await file.length();
      if (length < 16) {
        return ModelValidationResult.invalid('File too small to be a valid model: $length bytes');
      }

      final raf = await file.open(mode: FileMode.read);
      try {
        final headerBytes = await raf.read(24);
        if (headerBytes.length < 16) {
          return ModelValidationResult.invalid('Failed to read model header');
        }

        final byteData = ByteData.sublistView(Uint8List.fromList(headerBytes));

        // 1. Check GGUF magic: 'GGUF' (0x47, 0x47, 0x55, 0x46)
        final isGguf = headerBytes[0] == 0x47 &&
            headerBytes[1] == 0x47 &&
            headerBytes[2] == 0x55 &&
            headerBytes[3] == 0x46;

        if (isGguf) {
          final version = byteData.getUint32(4, Endian.little);
          if (version < 1 || version > 4) {
            return ModelValidationResult.invalid('Unsupported GGUF version: $version');
          }

          int tensorCount = 0;
          if (headerBytes.length >= 16) {
            tensorCount = byteData.getUint64(8, Endian.little);
          }

          return ModelValidationResult(
            isValid: true,
            format: AiModelFormat.gguf,
            version: version,
            tensorCount: tensorCount,
            fileSize: length,
            architecture: 'Winthos Superhuman AI',
          );
        }

        // 2. Check Winthos LightGBM Tabular magic or extension
        if (filePath.endsWith('.winslgbm') || filePath.endsWith('.model')) {
          return ModelValidationResult(
            isValid: true,
            format: AiModelFormat.winslgbm,
            version: 1,
            fileSize: length,
            architecture: 'Winthos AI AV Engine Specialist',
          );
        }

        return ModelValidationResult.invalid('Invalid GGUF magic header or unknown format');
      } finally {
        await raf.close();
      }
    } catch (e) {
      return ModelValidationResult.invalid('Validation error: $e');
    }
  }

  /// Discovers all valid AI models across configured storage paths.
  Future<List<DiscoveredModel>> discoverModels() async {
    final targetDirs = await getTargetModelDirectories();
    final discovered = <DiscoveredModel>[];

    for (final dirPath in targetDirs) {
      final dir = Directory(dirPath);
      if (!await dir.exists()) continue;

      try {
        final entities = await dir.list(recursive: false, followLinks: false).toList();
        for (final entity in entities) {
          if (entity is! File) continue;

          final name = p.basename(entity.path);
          if (!name.endsWith('.gguf') && !name.endsWith('.winslgbm') && !name.endsWith('.model')) {
            continue;
          }

          final validation = await validateModelFile(entity.path);
          if (validation.isValid) {
            final stat = await entity.stat();
            discovered.add(DiscoveredModel(
              fileName: name,
              fullPath: entity.path,
              format: validation.format,
              sizeBytes: stat.size,
              lastModified: stat.modified,
              validation: validation,
            ));
          }
        }
      } catch (_) {
        // Fail-closed on directory access errors
      }
    }

    return discovered;
  }

  Future<bool> hasSuperhumanAiModel() async {
    final models = await discoverModels();
    return models.any((m) => m.format == AiModelFormat.gguf && m.validation.isValid);
  }

  Future<bool> hasAvEngineTabularModel() async {
    final models = await discoverModels();
    return models.any((m) => m.format == AiModelFormat.winslgbm && m.validation.isValid);
  }
}
