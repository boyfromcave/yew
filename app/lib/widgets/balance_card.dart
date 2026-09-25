// The Home cards (plan §5.1): one large number, one sub-line, one accent per asset. The
// number animates only when it changes (D-W-9: motion where something happened).
import 'package:flutter/material.dart';

import '../theme.dart';

class BalanceCard extends StatelessWidget {
  const BalanceCard({
    super.key,
    required this.title,
    required this.amount,
    required this.accent,
    this.unit,
    this.subLines = const [],
    this.trailing,
  });

  final String title;
  final String amount;
  final Color accent;
  final String? unit;
  final List<String> subLines;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 18, 20, 18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(color: accent, shape: BoxShape.circle),
                ),
                const SizedBox(width: 8),
                Text(title, style: text.titleMedium?.copyWith(color: accent)),
                const Spacer(),
                ?trailing,
              ],
            ),
            const SizedBox(height: 10),
            AnimatedSwitcher(
              duration: confirmMotion,
              switchInCurve: Curves.easeOutCubic,
              transitionBuilder: (child, anim) => FadeTransition(
                opacity: anim,
                child: SlideTransition(
                  position: Tween(begin: const Offset(0, 0.15), end: Offset.zero).animate(anim),
                  child: child,
                ),
              ),
              child: Row(
                key: ValueKey(amount),
                crossAxisAlignment: CrossAxisAlignment.baseline,
                textBaseline: TextBaseline.alphabetic,
                children: [
                  Flexible(
                    child: FittedBox(
                      fit: BoxFit.scaleDown,
                      alignment: Alignment.centerLeft,
                      child: Text(amount, style: text.displayMedium),
                    ),
                  ),
                  if (unit != null) ...[
                    const SizedBox(width: 8),
                    Text(unit!, style: text.titleLarge?.copyWith(color: accent)),
                  ],
                ],
              ),
            ),
            for (final s in subLines)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(s, style: text.bodyMedium?.copyWith(color: text.bodySmall?.color)),
              ),
          ],
        ),
      ),
    );
  }
}
