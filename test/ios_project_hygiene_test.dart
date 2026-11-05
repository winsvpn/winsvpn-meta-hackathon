import 'dart:io';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('obsolete project copies and duplicate Info.plist are absent', () {
    expect(Directory('ios/Runner.xcodeproj').listSync().where((p) =>
      p.path.split('/').last.startsWith('project.pbxproj.')), isEmpty);
    expect(File('ios/Info.plist').existsSync(), isFalse);
  });
}
