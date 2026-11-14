// Shared helpers for the harmless ProcessGuard lab simulations.
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

static class Lab
{
    /// <summary>Duration in seconds from argv[0], clamped to 10..600 so a run can never be unbounded.</summary>
    public static int Duration(string[] args, int fallback = 120)
    {
        int value = fallback;
        if (args.Length > 0 && int.TryParse(args[0], out var parsed)) value = parsed;
        return Math.Clamp(value, 10, 600);
    }

    /// <summary>Starts a loopback-only echo listener; returns its port.</summary>
    public static int StartLoopbackListener(CancellationToken token)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        new Thread(() =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (!listener.Pending()) { Thread.Sleep(50); continue; }
                    var client = listener.AcceptTcpClient();
                    new Thread(() => Echo(client, token)) { IsBackground = true }.Start();
                }
                catch (SocketException) { break; }
            }
            listener.Stop();
        }) { IsBackground = true }.Start();
        return port;
    }

    static void Echo(TcpClient client, CancellationToken token)
    {
        using (client)
        {
            var stream = client.GetStream();
            var buffer = new byte[64];
            try
            {
                while (!token.IsCancellationRequested)
                {
                    int read = stream.Read(buffer, 0, buffer.Length);
                    if (read <= 0) break;
                    stream.Write(Encoding.ASCII.GetBytes("ACK\n"));
                }
            }
            catch (Exception) { }
        }
    }

    /// <summary>Opens <paramref name="count"/> loopback clients that send a small beacon every second.</summary>
    public static List<Thread> StartBeacons(int port, int count, CancellationToken token)
    {
        var threads = new List<Thread>();
        for (int i = 0; i < count; i++)
        {
            int id = i;
            var thread = new Thread(() =>
            {
                try
                {
                    using var client = new TcpClient();
                    client.Connect(IPAddress.Loopback, port);
                    var stream = client.GetStream();
                    var buffer = new byte[16];
                    while (!token.IsCancellationRequested)
                    {
                        stream.Write(Encoding.ASCII.GetBytes($"PG-LAB-BEACON {id}\n"));
                        stream.Read(buffer, 0, buffer.Length);
                        token.WaitHandle.WaitOne(1000);
                    }
                }
                catch (Exception) { }
            }) { IsBackground = true };
            thread.Start();
            threads.Add(thread);
        }
        return threads;
    }
}
