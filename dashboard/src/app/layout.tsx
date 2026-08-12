import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'PG-SQUEEZE Dashboard',
  description: 'eBPF-powered PostgreSQL observability dashboard',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="bg-[#0a0a0c] text-[#e4e4e7] antialiased">{children}</body>
    </html>
  )
}
