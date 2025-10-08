"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Shield, CheckCircle, AlertTriangle, XCircle, Scan } from "lucide-react"
import { cn } from "@/lib/utils"

type ScanResult = {
  status: "safe" | "suspicious" | "malicious"
  reasons: string[]
  url: string
  score: number
}

export default function PhishingScanner() {
  const [url, setUrl] = useState("")
  const [isScanning, setIsScanning] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)

  const handleScan = async () => {
    if (!url.trim()) return
    setIsScanning(true)
    try {
      const res = await fetch("http://localhost:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: url }),
      })

      if (!res.ok) throw new Error("Failed to scan")

      const data = await res.json()
      setResult({
        url: data.url,
        status: data.verdict.toLowerCase() as "safe" | "suspicious" | "malicious",
        reasons: data.reasons,
        score: data.score,
      })
    } catch (err) {
      console.error(err)
      setResult({
        url,
        status: "suspicious",
        reasons: ["Error scanning URL. Please try again later."],
        score: 0,
      })
    } finally {
      setIsScanning(false)
    }
  }

  const getStatusConfig = (status: ScanResult["status"]) => {
    switch (status) {
      case "safe":
        return {
          icon: CheckCircle,
          color: "text-green-600",
          bgColor: "bg-green-50",
          borderColor: "border-green-200",
          label: "Safe",
        }
      case "suspicious":
        return {
          icon: AlertTriangle,
          color: "text-amber-600",
          bgColor: "bg-amber-50",
          borderColor: "border-amber-200",
          label: "Suspicious",
        }
      case "malicious":
        return {
          icon: XCircle,
          color: "text-red-600",
          bgColor: "bg-red-50",
          borderColor: "border-red-200",
          label: "Malicious",
        }
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyan-50 via-blue-50 to-indigo-50">
      <div className="container mx-auto px-4 py-12">
        <div className="max-w-2xl mx-auto space-y-8">
          {/* Header */}
          <div className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="p-3 bg-primary/10 rounded-full">
                <Shield className="h-8 w-8 text-primary" />
              </div>
            </div>
            <h1 className="text-4xl font-bold text-primary text-balance">Mobile Security – URL Scanner</h1>
            <p className="text-lg text-muted-foreground text-pretty">
              Protect yourself from phishing attacks by scanning suspicious URLs
            </p>
          </div>

          {/* Scanner Card */}
          <Card className="shadow-lg border-0 bg-card/80 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-card-foreground">
                <Scan className="h-5 w-5" />
                URL Scanner
              </CardTitle>
              <CardDescription>Enter a URL to check for potential phishing or malicious content</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url" className="text-card-foreground font-medium">
                  URL to scan
                </Label>
                <Input
                  id="url"
                  type="url"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="bg-input border-border focus:ring-primary/20"
                  onKeyDown={(e) => e.key === "Enter" && handleScan()}
                />
              </div>
              <Button
                onClick={handleScan}
                disabled={!url.trim() || isScanning}
                className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
              >
                {isScanning ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-2 border-primary-foreground border-t-transparent mr-2" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Scan className="h-4 w-4 mr-2" />
                    Scan URL
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Results Card */}
          {result && (
            <Card
              className={cn(
                "shadow-lg border-2 transition-all duration-300 animate-in slide-in-from-bottom-4",
                getStatusConfig(result.status).bgColor,
                getStatusConfig(result.status).borderColor,
              )}
            >
              <CardHeader>
                <CardTitle className="flex items-center gap-3">
                  {(() => {
                    const StatusIcon = getStatusConfig(result.status).icon
                    return <StatusIcon className={cn("h-6 w-6", getStatusConfig(result.status).color)} />
                  })()}
                  <span className={getStatusConfig(result.status).color}>
                    {getStatusConfig(result.status).label} (Score: {result.score})
                  </span>
                </CardTitle>
                <CardDescription className="font-mono text-sm break-all">{result.url}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <h4 className="font-semibold text-foreground">Analysis Results:</h4>
                  <ul className="space-y-2">
                    {result.reasons.map((reason, index) => (
                      <li key={index} className="flex items-start gap-2 text-sm">
                        <div className="h-1.5 w-1.5 rounded-full bg-current mt-2 flex-shrink-0" />
                        <span className="text-foreground/80">{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Info Card */}
          <Card className="bg-muted/50 border-border/50">
            <CardContent className="pt-6">
              <div className="text-center text-sm text-muted-foreground">
                <p className="text-pretty">
                  This scanner analyzes URLs for potential phishing indicators including domain reputation, SSL
                  certificates, and suspicious patterns. Always exercise caution when visiting unknown websites.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
