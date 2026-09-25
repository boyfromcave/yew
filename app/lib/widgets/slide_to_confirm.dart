// "One gesture to send" (plan §5.2): a slider that fires once dragged to the end. No
// package; a GestureDetector over a track. Disabled while busy.
import 'package:flutter/material.dart';

class SlideToConfirm extends StatefulWidget {
  const SlideToConfirm({
    super.key,
    required this.label,
    required this.onConfirmed,
    required this.color,
    this.enabled = true,
  });

  final String label;
  final Future<void> Function() onConfirmed;
  final Color color;
  final bool enabled;

  @override
  State<SlideToConfirm> createState() => _SlideToConfirmState();
}

class _SlideToConfirmState extends State<SlideToConfirm> {
  double _x = 0;
  bool _busy = false;
  static const double _knob = 56;
  static const double _height = 60;

  @override
  Widget build(BuildContext context) {
    final on = widget.enabled && !_busy;
    return LayoutBuilder(
      builder: (context, c) {
        final max = c.maxWidth - _knob - 4;
        return Semantics(
          button: true,
          label: widget.label,
          child: GestureDetector(
            key: const Key('slide-to-confirm'),
            onHorizontalDragUpdate: on
                ? (d) => setState(() => _x = (_x + d.delta.dx).clamp(0, max))
                : null,
            onHorizontalDragEnd: on
                ? (_) async {
                    if (_x >= max * 0.9) {
                      setState(() {
                        _x = max;
                        _busy = true;
                      });
                      try {
                        await widget.onConfirmed();
                      } finally {
                        if (mounted) {
                          setState(() {
                            _busy = false;
                            _x = 0;
                          });
                        }
                      }
                    } else {
                      setState(() => _x = 0);
                    }
                  }
                : null,
            // A tap-and-hold-free path for tests and accessibility: a long press confirms.
            onLongPress: on ? () => widget.onConfirmed() : null,
            child: Container(
              height: _height,
              decoration: BoxDecoration(
                color: widget.color.withValues(alpha: on ? 0.18 : 0.08),
                borderRadius: BorderRadius.circular(_height / 2),
              ),
              child: Stack(
                alignment: Alignment.center,
                children: [
                  Text(
                    _busy ? 'Sending…' : widget.label,
                    style: TextStyle(
                      fontWeight: FontWeight.w600,
                      color: on ? widget.color : Theme.of(context).disabledColor,
                    ),
                  ),
                  AnimatedPositioned(
                    duration: const Duration(milliseconds: 120),
                    left: 2 + _x,
                    child: Container(
                      width: _knob,
                      height: _knob,
                      decoration: BoxDecoration(
                        color: on ? widget.color : Theme.of(context).disabledColor,
                        shape: BoxShape.circle,
                      ),
                      child: _busy
                          ? const Padding(
                              padding: EdgeInsets.all(16),
                              child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                            )
                          : const Icon(Icons.arrow_forward_rounded, color: Colors.white),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}
