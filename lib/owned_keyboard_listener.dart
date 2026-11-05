import 'package:flutter/widgets.dart';

/// A keyboard listener that retains and disposes its own non-traversable node.
class OwnedKeyboardListener extends StatefulWidget {
  const OwnedKeyboardListener({
    super.key,
    required this.child,
    this.onKeyEvent,
    this.autofocus = false,
    this.includeSemantics = true,
  });

  final Widget child;
  final ValueChanged<KeyEvent>? onKeyEvent;
  final bool autofocus;
  final bool includeSemantics;

  @override
  State<OwnedKeyboardListener> createState() => _OwnedKeyboardListenerState();
}

class _OwnedKeyboardListenerState extends State<OwnedKeyboardListener> {
  late final FocusNode _focusNode;

  @override
  void initState() {
    super.initState();
    _focusNode = FocusNode(skipTraversal: true);
  }

  @override
  void dispose() {
    _focusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return KeyboardListener(
      focusNode: _focusNode,
      autofocus: widget.autofocus,
      includeSemantics: widget.includeSemantics,
      onKeyEvent: widget.onKeyEvent,
      child: widget.child,
    );
  }
}
