import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ZKPassport Discord Verification",
  description: "Secure Discord admin verification using ZKPassport",
  keywords: ["ZKPassport", "Discord", "verification", "zero-knowledge"],
  authors: [{ name: "ZKPassport Team" }],
};

export const viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default async function RootLayout({
    children,
  }: {
    children: React.ReactNode;
  }) {
    // Get nonce from headers (Next.js will pass it)
    const headersList = await headers();
    const nonce = headersList.get('x-nonce') || '';

    return (
      <html lang="en">
       <body className={inter.className}>
           {/* External security script - no inline JavaScript */}
           <script src="/security.js" async nonce={nonce}></script>
           <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
           <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
             <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
               <div className="flex justify-between items-center py-4">
                 <div className="flex items-center">
                   <h1 className="text-xl font-semibold text-gray-900 dark:text-white">
                     ZKPassport Discord Verifier
                   </h1>
                 </div>
                 <div className="text-sm text-gray-500 dark:text-gray-400">
                   Secure • Private • Decentralized
                 </div>
               </div>
             </div>
           </header>
           <main className="flex-1">
             {children}
           </main>
           <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-auto">
             <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
               <div className="text-center text-sm text-gray-500 dark:text-gray-400">
                 <p>
                   Powered by{" "}
                   <a
                     href="https://zkpassport.id"
                     target="_blank"
                     rel="noopener noreferrer"
                     className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                   >
                     ZKPassport
                   </a>
                 </p>
               </div>
             </div>
           </footer>
         </div>
       </body>
     </html>
   );
 }