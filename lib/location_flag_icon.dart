import 'package:country_flags/country_flags.dart';
import 'package:flutter/material.dart';

const int _regionalIndicatorA = 0x1F1E6;
const int _regionalIndicatorZ = 0x1F1FF;

String? countryCodeFromSlugOrName(String? text) {
  if (text == null) return null;
  final clean = text.trim().toLowerCase();
  if (clean.isEmpty) return null;

  if (clean.contains('canada') ||
      clean.contains('montreal') ||
      clean.contains('toronto') ||
      clean.contains('vancouver') ||
      clean.startsWith('ca-') ||
      clean.startsWith('ca1') ||
      clean.contains('ca1')) {
    return 'CA';
  }
  if (clean.contains('germany') ||
      clean.contains('deutschland') ||
      clean.contains('falkenstein') ||
      clean.contains('frankfurt') ||
      clean.contains('berlin') ||
      clean.startsWith('de-') ||
      clean.startsWith('de1') ||
      clean.contains('de1')) {
    return 'DE';
  }
  if (clean.contains('spain') ||
      clean.contains('españa') ||
      clean.contains('espana') ||
      clean.contains('madrid') ||
      clean.contains('barcelona') ||
      clean.startsWith('es-') ||
      clean.startsWith('es1') ||
      clean.contains('es1')) {
    return 'ES';
  }
  if (clean.contains('united states') ||
      clean.contains('usa') ||
      clean.contains('america') ||
      clean.startsWith('us-') ||
      clean.startsWith('us1')) {
    return 'US';
  }
  if (clean.contains('united kingdom') ||
      clean.contains('britain') ||
      clean.contains('england') ||
      clean.contains('london') ||
      clean.startsWith('uk-') ||
      clean.startsWith('gb-')) {
    return 'GB';
  }
  if (clean.contains('france') ||
      clean.contains('paris') ||
      clean.startsWith('fr-')) {
    return 'FR';
  }
  if (clean.contains('netherlands') ||
      clean.contains('amsterdam') ||
      clean.startsWith('nl-')) {
    return 'NL';
  }
  if (clean.contains('switzerland') ||
      clean.contains('zurich') ||
      clean.startsWith('ch-')) {
    return 'CH';
  }
  if (clean.contains('sweden') ||
      clean.contains('stockholm') ||
      clean.startsWith('se-')) {
    return 'SE';
  }
  if (clean.contains('finland') ||
      clean.contains('helsinki') ||
      clean.startsWith('fi-')) {
    return 'FI';
  }
  if (clean.contains('norway') ||
      clean.contains('oslo') ||
      clean.startsWith('no-')) {
    return 'NO';
  }
  if (clean.contains('italy') ||
      clean.contains('italia') ||
      clean.contains('rome') ||
      clean.startsWith('it-')) {
    return 'IT';
  }
  if (clean.contains('japan') ||
      clean.contains('tokyo') ||
      clean.startsWith('jp-')) {
    return 'JP';
  }
  if (clean.contains('singapore') || clean.startsWith('sg-')) {
    return 'SG';
  }
  if (clean.contains('australia') ||
      clean.contains('sydney') ||
      clean.startsWith('au-')) {
    return 'AU';
  }
  if (clean.contains('brazil') ||
      clean.contains('brasil') ||
      clean.startsWith('br-')) {
    return 'BR';
  }
  if (clean.contains('india') ||
      clean.contains('mumbai') ||
      clean.startsWith('in-')) {
    return 'IN';
  }
  return null;
}

/// Returns a supported ISO country code from either an alpha-2 value or a
/// regional-indicator flag, falling back deterministically to location metadata.
String? countryCodeFromFlagValue(
  dynamic value, {
  String? locationName,
  String? slug,
}) {
  final inferred =
      countryCodeFromSlugOrName(slug) ?? countryCodeFromSlugOrName(locationName);

  final raw = (value ?? '').toString().trim();
  String? candidate;
  if (raw.isNotEmpty) {
    final upper = raw.toUpperCase();
    if (RegExp(r'^[A-Z]{2}$').hasMatch(upper)) {
      candidate = upper;
    } else {
      final runes = raw.runes.toList(growable: false);
      if (runes.length == 2 &&
          runes.every(
            (rune) => rune >= _regionalIndicatorA && rune <= _regionalIndicatorZ,
          )) {
        candidate = String.fromCharCodes(
          runes.map((rune) => 65 + rune - _regionalIndicatorA),
        );
      }
    }
  }

  // Reject the legacy Kansas Hub default "GL" (Greenland) when the location is not Greenland
  if (candidate == 'GL') {
    final lowerName = (locationName ?? '').toLowerCase();
    final lowerSlug = (slug ?? '').toLowerCase();
    final isActuallyGreenland = lowerName.contains('greenland') ||
        lowerName.contains('kalaallit') ||
        lowerSlug.contains('greenland');
    if (!isActuallyGreenland && inferred != null) {
      return inferred;
    }
  }

  if (candidate != null && FlagCode.fromCountryCode(candidate) != null) {
    return candidate;
  }
  return inferred;
}

class LocationFlagIcon extends StatelessWidget {
  const LocationFlagIcon({
    super.key,
    required this.flagValue,
    this.locationName = '',
    this.slug = '',
    this.width = 28,
    this.height = 20,
  });

  final dynamic flagValue;
  final String locationName;
  final String slug;
  final double width;
  final double height;

  @override
  Widget build(BuildContext context) {
    final countryCode = countryCodeFromFlagValue(
      flagValue,
      locationName: locationName,
      slug: slug,
    );
    final name = locationName.trim();
    final semanticsLabel = countryCode == null
        ? (name.isEmpty ? 'Global location' : '$name location')
        : (name.isEmpty ? '$countryCode flag' : '$name flag');

    return Semantics(
      container: true,
      image: countryCode != null,
      label: semanticsLabel,
      child: ExcludeSemantics(
        child: countryCode == null
            ? SizedBox(
                width: width,
                height: height,
                child: Icon(Icons.public, size: height),
              )
            : CountryFlag.fromCountryCode(
                countryCode,
                theme: ImageTheme(
                  width: width,
                  height: height,
                  shape: const RoundedRectangle(3),
                ),
              ),
      ),
    );
  }
}
