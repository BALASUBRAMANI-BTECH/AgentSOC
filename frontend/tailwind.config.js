/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#080c14",
          card: "#0f172a",
          border: "#1e293b",
          highlight: "#1e293b",
          accent: "#3b82f6",
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#10b981",
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace']
      }
    },
  },
  plugins: [],
}

