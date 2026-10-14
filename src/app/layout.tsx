import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Hermes3D",
  description: "Focused operator studio for the Hermes gateway.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html:
              "(function(){try{var t=localStorage.getItem('theme');var m=window.matchMedia('(prefers-color-scheme: dark)').matches;var d=t?t==='dark':m;document.documentElement.classList.toggle('dark',d);}catch(e){}})();",
          }}
        />
      </head>
      <body className="antialiased">
        <main className="h-screen w-screen overflow-hidden bg-background">
          {children}
        </main>
      </body>
    </html>
  );
}
