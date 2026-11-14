// Masquerading "explorer" that spawns several child processes (ping to loopback only).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

int duration = Lab.Duration(args);
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(duration));
int port = Lab.StartLoopbackListener(cts.Token);
Lab.StartBeacons(port, 4, cts.Token);
var children = new List<Process>();
for (int i = 0; i < 6; i++)
{
    var info = new ProcessStartInfo("cmd.exe", $"/c ping -n {duration} 127.0.0.1 >nul")
    { UseShellExecute = false, CreateNoWindow = true };
    children.Add(Process.Start(info)!);
}
Console.WriteLine("[PG-LAB] dropper-like simulation spawned 6 children");
cts.Token.WaitHandle.WaitOne();
foreach (var child in children)
{
    try { if (!child.HasExited) child.Kill(entireProcessTree: true); } catch (Exception) { }
}
