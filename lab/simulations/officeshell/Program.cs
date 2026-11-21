// Fake "WINWORD.EXE" spawning an encoded PowerShell command (LOLBin pattern).
// The PowerShell child only beacons to a loopback listener hosted by this process.
using System;
using System.Diagnostics;
using System.Text;
using System.Threading;

int duration = Lab.Duration(args);
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(duration));
int port = Lab.StartLoopbackListener(cts.Token);
string script =
    $"$end=(Get-Date).AddSeconds({duration});" +
    $"$c=New-Object Net.Sockets.TcpClient('127.0.0.1',{port});$s=$c.GetStream();$b=New-Object byte[] 16;" +
    "while((Get-Date) -lt $end){$m=[Text.Encoding]::ASCII.GetBytes(\"PG-LAB-PS`n\");" +
    "$s.Write($m,0,$m.Length);[void]$s.Read($b,0,16);Start-Sleep -Milliseconds 700};$c.Close()";
string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
var info = new ProcessStartInfo("powershell.exe",
    $"-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}")
{ UseShellExecute = false, CreateNoWindow = true };
using var child = Process.Start(info)!;
Console.WriteLine($"[PG-LAB] office-shell simulation started powershell PID {child.Id}");
cts.Token.WaitHandle.WaitOne();
try { if (!child.HasExited) child.Kill(entireProcessTree: true); } catch (Exception) { }
