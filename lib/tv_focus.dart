import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// A focusable, scrollable vertical list for D-pad / arrow-key navigation on
/// TV.
///
/// The list owns a [FocusNode] that participates in the ambient [FocusScope]
/// (the widget wraps itself in a [FocusScope] so it can be operated
/// independently of the rest of the screen) and handles arrow / D-pad key
/// events to move an explicit selection index up and down, automatically
/// scrolling the active item into view. Select / enter / game-button-A /
/// space invoke [onSelected] with the current index.
///
/// This is the missing piece that makes a TV install usable with a remote:
/// without it the list is not reachable by the D-pad and the user cannot
/// scroll or choose an entry.
class TvFocusList extends StatefulWidget {
  const TvFocusList({
    super.key,
    required this.itemCount,
    required this.itemBuilder,
    this.initialIndex = 0,
    this.itemExtent = 72.0,
    this.autofocus = false,
    this.focusNode,
    this.onSelected,
    this.onSelectionChanged,
    this.focusColor = const Color(0xFFFFD21F),
  });

  /// Number of items in the list.
  final int itemCount;

  /// Builds the widget for the item at [index].
  final IndexedWidgetBuilder itemBuilder;

  /// Index selected before any key event.
  final int initialIndex;

  /// Fixed vertical extent of each item, used to scroll the active item into
  /// view. Defaults to 72 logical pixels.
  final double itemExtent;

  /// Whether this list should request focus automatically on first build.
  final bool autofocus;

  /// Optional externally-owned [FocusNode]. If omitted the list owns one.
  final FocusNode? focusNode;

  /// Invoked with the current index when the user presses select / enter.
  final ValueChanged<int>? onSelected;

  /// Reports every selection change (including initial). Used by tests and by
  /// callers that need to react when the highlighted row moves.
  final ValueChanged<int>? onSelectionChanged;

  /// Highlight color drawn around the currently selected row.
  final Color focusColor;

  @override
  State<TvFocusList> createState() => _TvFocusListState();
}

class _TvFocusListState extends State<TvFocusList> {
  late int _selected;
  late ScrollController _scroll;
  late FocusNode _focus;

  @override
  void initState() {
    super.initState();
    _selected = widget.itemCount > 0
        ? widget.initialIndex.clamp(0, widget.itemCount - 1)
        : 0;
    _scroll = ScrollController();
    _focus = widget.focusNode ?? FocusNode();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || widget.itemCount <= 0) return;
      widget.onSelectionChanged?.call(_selected);
    });
  }

  @override
  void didUpdateWidget(TvFocusList oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.itemCount <= 0) {
      _selected = 0;
    } else {
      _selected = _selected.clamp(0, widget.itemCount - 1);
    }
  }

  @override
  void dispose() {
    _scroll.dispose();
    if (widget.focusNode == null) _focus.dispose();
    super.dispose();
  }

  KeyEventResult _handleKey(FocusNode node, KeyEvent event) {
    if (event is! KeyDownEvent) return KeyEventResult.ignored;
    final key = event.logicalKey;
    if (key == LogicalKeyboardKey.arrowDown) {
      _move(1);
      return KeyEventResult.handled;
    }
    if (key == LogicalKeyboardKey.arrowUp) {
      _move(-1);
      return KeyEventResult.handled;
    }
    if (key == LogicalKeyboardKey.select ||
        key == LogicalKeyboardKey.enter ||
        key == LogicalKeyboardKey.gameButtonA ||
        key == LogicalKeyboardKey.space) {
      if (widget.itemCount <= 0) return KeyEventResult.handled;
      widget.onSelected?.call(_selected);
      return KeyEventResult.handled;
    }
    return KeyEventResult.ignored;
  }

  void _move(int delta) {
    if (widget.itemCount <= 0) return;
    final next = (_selected + delta).clamp(0, widget.itemCount - 1);
    if (next == _selected) return;
    setState(() => _selected = next);
    widget.onSelectionChanged?.call(_selected);
    _scrollSelectedIntoView();
  }

  void _scrollSelectedIntoView() {
    if (!_scroll.hasClients) return;
    final target =
        (_selected * widget.itemExtent).clamp(0.0, _scroll.position.maxScrollExtent);
    _scroll.animateTo(
      target,
      duration: const Duration(milliseconds: 120),
      curve: Curves.easeOut,
    );
  }

  @override
  Widget build(BuildContext context) {
    return FocusScope(
      child: Focus(
        focusNode: _focus,
        autofocus: widget.autofocus,
        onKeyEvent: _handleKey,
        child: ListView.builder(
          controller: _scroll,
          itemExtent: widget.itemExtent,
          itemCount: widget.itemCount,
          itemBuilder: (context, index) {
            return _SelectedHighlight(
              selected: index == _selected,
              color: widget.focusColor,
              child: widget.itemBuilder(context, index),
            );
          },
        ),
      ),
    );
  }
}

/// Draws a visible border around the selected row so the D-pad position is
/// discernible from three metres, in line with the rest of the TV styling.
class _SelectedHighlight extends StatelessWidget {
  const _SelectedHighlight({
    required this.selected,
    required this.color,
    required this.child,
  });

  final bool selected;
  final Color color;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 120),
      decoration: selected
          ? BoxDecoration(
              border: Border.all(color: color, width: 3.5),
              borderRadius: BorderRadius.circular(10),
              boxShadow: [
                BoxShadow(
                  color: color.withValues(alpha: 0.55),
                  blurRadius: 16,
                ),
              ],
            )
          : BoxDecoration(
              border: Border.all(color: Colors.transparent, width: 1),
              borderRadius: BorderRadius.circular(10),
            ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(9),
        child: child,
      ),
    );
  }
}
