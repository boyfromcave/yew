// The root: theme (light and dark), the one AppState, and the choice between Onboarding, the
// lock screen and the shell (Home, Yellowback and History behind three tabs; plan §1.1, §5.3).
import 'package:flutter/material.dart';

import 'screens/history.dart';
import 'screens/home.dart';
import 'screens/onboarding.dart';
import 'screens/yellowback.dart';
import 'state/app_scope.dart';
import 'state/app_state.dart';
import 'theme.dart';

class YewApp extends StatelessWidget {
  const YewApp({super.key, required this.state});

  final AppState state;

  @override
  Widget build(BuildContext context) {
    return AppScope(
      state: state,
      child: MaterialApp(
        title: 'YEW',
        debugShowCheckedModeBanner: false,
        theme: buildTheme(Brightness.light),
        darkTheme: buildTheme(Brightness.dark),
        themeMode: ThemeMode.system,
        home: const _Root(),
      ),
    );
  }
}

class _Root extends StatefulWidget {
  const _Root();

  @override
  State<_Root> createState() => _RootState();
}

class _RootState extends State<_Root> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final app = AppScope.read(context);
      if (!app.loaded) app.load();
    });
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    if (!app.loaded) return const Scaffold(body: Center(child: CircularProgressIndicator()));
    if (!app.hasWallet) return const OnboardingScreen();
    if (!app.unlocked) return const LockScreen();
    return const Shell();
  }
}

class LockScreen extends StatefulWidget {
  const LockScreen({super.key});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  bool _busy = false;

  Future<void> _unlock() async {
    setState(() => _busy = true);
    await AppScope.read(context).unlock();
    if (mounted) setState(() => _busy = false);
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!AppScope.read(context).explicitLock) _unlock();
    });
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final c = yewColors(context);
    final t = Theme.of(context).textTheme;
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text('YEW', style: t.displayLarge?.copyWith(color: c.yed)),
              const SizedBox(height: 8),
              Text('Locked', style: t.titleMedium),
              if (app.lastError != null) ...[
                const SizedBox(height: 16),
                Text(app.lastError!, key: const Key('error'), textAlign: TextAlign.center, style: TextStyle(color: c.danger)),
              ],
              const SizedBox(height: 32),
              FilledButton(key: const Key('unlock'), onPressed: _busy ? null : _unlock, child: Text(_busy ? 'Unlocking…' : 'Unlock')),
            ],
          ),
        ),
      ),
    );
  }
}

class Shell extends StatefulWidget {
  const Shell({super.key});

  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  int _tab = 0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: IndexedStack(index: _tab, children: const [HomeScreen(), YellowbackScreen(), HistoryScreen()]),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(key: Key('tab-home'), icon: Icon(Icons.account_balance_wallet_outlined), selectedIcon: Icon(Icons.account_balance_wallet), label: 'Wallet'),
          NavigationDestination(key: Key('tab-yellowback'), icon: Icon(Icons.lock_outline_rounded), selectedIcon: Icon(Icons.lock_rounded), label: 'Yellowback'),
          NavigationDestination(key: Key('tab-history'), icon: Icon(Icons.receipt_long_outlined), selectedIcon: Icon(Icons.receipt_long), label: 'History'),
        ],
      ),
    );
  }
}
