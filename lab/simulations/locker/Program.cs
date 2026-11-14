// Ransomware-like I/O simulation. Touches ONLY dummy files it creates in its own temp folder.
using System;
using System.IO;
using System.Threading;

using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Lab.Duration(args)));
string root = Path.Combine(Path.GetTempPath(), "processguard_lab_locker_" + Environment.ProcessId);
Directory.CreateDirectory(root);
var random = new Random(42);
var content = new byte[64 * 1024];
try
{
    for (int i = 0; i < 120; i++)
    {
        random.NextBytes(content);
        File.WriteAllBytes(Path.Combine(root, $"document_{i:D3}.txt"), content);
    }
    Console.WriteLine($"[PG-LAB] locker simulation on dummy files in {root}");
    while (!cts.IsCancellationRequested)
    {
        foreach (var file in Directory.GetFiles(root))
        {
            if (cts.IsCancellationRequested) break;
            var data = File.ReadAllBytes(file);
            for (int k = 0; k < data.Length; k++) data[k] ^= 0x5A;   // reversible XOR, not real crypto
            string target = file.EndsWith(".locked") ? file[..^7] : file + ".locked";
            File.WriteAllBytes(target, data);
            File.Delete(file);
            Thread.Sleep(5);
        }
    }
}
finally
{
    Directory.Delete(root, recursive: true);
}
