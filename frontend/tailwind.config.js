/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: '#0B0D0F',
          panel: '#15181B',
          line: '#262B30',
        },
        dossier: {
          DEFAULT: '#D98E3B',
          dim: '#8A5E2A',
          paper: '#1C1814',
        },
        terminal: {
          DEFAULT: '#4DFFB8',
          dim: '#2E9C72',
        },
        alert: {
          DEFAULT: '#FF5C5C',
          dim: '#8C2E2E',
        },
        bone: {
          DEFAULT: '#E8E6E1',
          muted: '#8A8780',
        },
      },
      fontFamily: {
        stamp: ['"Special Elite"', 'monospace'],
        body: ['"IBM Plex Sans"', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
}
