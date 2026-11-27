export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        navy: { 950: '#050b18', 900: '#0a1428', 800: '#0f1d3a', 700: '#16294f', 600: '#1e3a6b' },
        cyan: { 400: '#22d3ee', 500: '#06b6d4' },
        neon: { 400: '#34d399', 500: '#10b981' },
      },
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], mono: ['JetBrains Mono', 'ui-monospace', 'monospace'] },
    },
  },
  plugins: [],
}
