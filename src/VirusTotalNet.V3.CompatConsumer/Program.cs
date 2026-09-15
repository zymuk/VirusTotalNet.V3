using VirusTotalNet.V3;
using VirusTotalNet.V3.Core;

namespace CompatConsumer
{
    class Program
    {
        static void Main(string[] args)
        {
            var options = new VirusTotalOptions
            {
                ApiKey = "test-key",
                RequestsPerMinute = 4,
                RequestsPerDay = 500
            };

            using var client = new VtClient(options, new System.Net.Http.HttpClient());

            // Basic test: check VtClient type exists
            Console.WriteLine("CompatConsumer netstandard2.0 build successful");
            Console.WriteLine($"VtClient type: {typeof(VtClient).Namespace}.{typeof(VtClient).Name}");

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }
    }
}