import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, Info, Loader, Server, Shield } from "lucide-react";
import { useState } from "react";

// Spinner Component
const LoadingSpinner = () => (
  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <div className="bg-white p-6 rounded-lg shadow-xl flex flex-col items-center">
      <div className="animate-spin">
        <Loader className="h-8 w-8 text-blue-500" />
      </div>
      <div className="mt-4 text-lg font-medium">Scanning Ports...</div>
      <div className="text-sm text-gray-500 mt-2">
        This may take a few moments
      </div>
      <div className="flex space-x-1 mt-3">
        <div
          className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"
          style={{ animationDelay: "0s" }}
        ></div>
        <div
          className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"
          style={{ animationDelay: "0.2s" }}
        ></div>
        <div
          className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"
          style={{ animationDelay: "0.4s" }}
        ></div>
      </div>
    </div>
  </div>
);

const PortScanner = () => {
  const [ipRange, setIpRange] = useState("");
  const [portRange, setPortRange] = useState("");
  const [scanMethod, setScanMethod] = useState("tcp");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState("");
  const [showMethodInfo, setShowMethodInfo] = useState(false);
  const [progress, setProgress] = useState(0);

  const scanMethods: { [key: string]: { name: string; description: string } } =
    {
      tcp: {
        name: "TCP Connect Scan",
        description:
          "Completes the full TCP three-way handshake. Most reliable but easily detected.",
      },
      udp: {
        name: "UDP Scan",
        description:
          "Sends UDP packets to detect open UDP ports. Less reliable but can find UDP services.",
      },
      syn: {
        name: "SYN Scan (Half-open)",
        description:
          "Sends SYN packets without completing handshake. Stealthier but requires privileges.",
      },
    };

  // Common service port mappings
  const commonPorts = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
  };

  const updateScanMethod = (method: string) => {
    setError("");
    setResults([]);
    setProgress(0);
    setResults([]);
    setScanMethod(method);
  };

  const validateInput = () => {
    // Basic IP range validation
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(-(\d{1,3}\.){3}\d{1,3})?$/;
    if (!ipPattern.test(ipRange)) {
      setError(
        "Invalid IP range format. Use format: 192.168.1.1 or 192.168.1.1-192.168.1.255"
      );
      return false;
    }

    // Basic port range validation
    const portPattern = /^\d+(-\d+)?$/;
    if (!portPattern.test(portRange)) {
      setError("Invalid port range format. Use format: 80 or 80-443");
      return false;
    }

    return true;
  };

  const simulateScan = () => {
    if (!validateInput()) return;

    setScanning(true);
    setError("");
    setResults([]);
    setProgress(0);

    // Simulate different results based on scan method
    const sampleResults = {
      tcp: [
        { ip: "192.168.1.1", port: 80, status: "open", service: "HTTP" },
        { ip: "192.168.1.1", port: 443, status: "open", service: "HTTPS" },
        { ip: "192.168.1.1", port: 22, status: "open", service: "SSH" },
      ],
      udp: [
        { ip: "192.168.1.1", port: 53, status: "open", service: "DNS" },
        { ip: "192.168.1.1", port: 161, status: "open", service: "SNMP" },
      ],
      syn: [
        { ip: "192.168.1.1", port: 80, status: "open", service: "HTTP" },
        { ip: "192.168.1.1", port: 443, status: "open", service: "HTTPS" },
        { ip: "192.168.1.1", port: 22, status: "filtered", service: "SSH" },
      ],
    };

    // Simulate scanning progress
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + Math.random() * 20;
      });
    }, 500);

    // Simulate scanning delay
    setTimeout(() => {
      clearInterval(progressInterval);
      setProgress(100);
      setResults(sampleResults[scanMethod]);
      setScanning(false);
    }, 3000);
  };

  return (
    <div className="max-w-4xl mx-auto p-4">
      {scanning && <LoadingSpinner />}

      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-6 w-6" />
            Network Port Scanner
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert className="mb-6">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Important Notice</AlertTitle>
            <AlertDescription>
              This tool is for educational purposes and authorized network
              diagnostics only. Always ensure you have permission to scan target
              networks.
            </AlertDescription>
          </Alert>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">
                IP Range:
              </label>
              <input
                type="text"
                className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500"
                placeholder="e.g., 192.168.1.1 or 192.168.1.1-192.168.1.255"
                value={ipRange}
                onChange={(e) => setIpRange(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">
                Port Range:
              </label>
              <input
                type="text"
                className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500"
                placeholder="e.g., 80 or 80-443"
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">
                Scan Method
                <button
                  className="ml-2 text-blue-500 hover:text-blue-600"
                  onClick={() => setShowMethodInfo(!showMethodInfo)}
                >
                  <Info className="h-4 w-4 inline" />
                </button>
              </label>
              <select
                className="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500"
                value={scanMethod}
                onChange={(e) => updateScanMethod(e.target.value)}
              >
                <option value="tcp">TCP Connect Scan</option>
                <option value="udp">UDP Scan</option>
                <option value="syn">SYN Scan (Half-open)</option>
              </select>
            </div>

            {showMethodInfo && (
              <div className="bg-gray-50 p-4 rounded-lg space-y-2">
                <h3 className="font-medium">Scanning Methods:</h3>
                {Object.entries(scanMethods).map(([key, method]) => (
                  <div key={key} className="ml-4">
                    <p className="font-medium">{method.name}:</p>
                    <p className="text-sm text-gray-600">
                      {method.description}
                    </p>
                  </div>
                ))}
              </div>
            )}

            {error && (
              <Alert variant="destructive">
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <button
              className={`w-full p-2 rounded text-white ${
                scanning
                  ? "bg-gray-500 cursor-not-allowed"
                  : "bg-blue-500 hover:bg-blue-600"
              }`}
              onClick={simulateScan}
              disabled={scanning}
            >
              {scanning ? "Scanning..." : "Start Scan"}
            </button>

            {scanning && (
              <div className="w-full bg-gray-200 rounded-full h-2.5 mt-2">
                <div
                  className="bg-blue-500 h-2.5 rounded-full transition-all duration-300 ease-in-out"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {results.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-6 w-6" />
              Scan Results ({scanMethods[scanMethod].name})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-gray-100">
                    <th className="p-2 text-left">IP Address</th>
                    <th className="p-2 text-left">Port</th>
                    <th className="p-2 text-left">Status</th>
                    <th className="p-2 text-left">Service</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((result, index) => (
                    <tr key={index} className="border-t">
                      <td className="p-2">{result.ip}</td>
                      <td className="p-2">{result.port}</td>
                      <td className="p-2">
                        <span
                          className={`px-2 py-1 rounded text-sm ${
                            result.status === "open"
                              ? "bg-green-100 text-green-800"
                              : result.status === "filtered"
                              ? "bg-yellow-100 text-yellow-800"
                              : "bg-red-100 text-red-800"
                          }`}
                        >
                          {result.status}
                        </span>
                      </td>
                      <td className="p-2">{result.service}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default PortScanner;
