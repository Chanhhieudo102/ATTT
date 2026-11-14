// Masquerading + C2-like beaconing simulation. Loopback only; no payload.
using System;
using System.Threading;

using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Lab.Duration(args)));
int port = Lab.StartLoopbackListener(cts.Token);
Lab.StartBeacons(port, 16, cts.Token);
Console.WriteLine($"[PG-LAB] beacon simulation on 127.0.0.1:{port}");
cts.Token.WaitHandle.WaitOne();
