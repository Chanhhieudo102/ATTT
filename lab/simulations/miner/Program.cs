// Resource-hijacking (coin-miner-like) simulation: bounded CPU hashing, nothing else.
using System;
using System.Security.Cryptography;
using System.Threading;

using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Lab.Duration(args)));
int workers = Math.Max(1, Environment.ProcessorCount / 2);
var threads = new Thread[workers];
for (int i = 0; i < workers; i++)
{
    threads[i] = new Thread(() =>
    {
        var block = new byte[32];
        while (!cts.IsCancellationRequested)
            for (int n = 0; n < 5000; n++) block = SHA256.HashData(block);
    }) { IsBackground = true };
    threads[i].Start();
}
Console.WriteLine($"[PG-LAB] miner-like simulation with {workers} worker threads");
foreach (var thread in threads) thread.Join();
