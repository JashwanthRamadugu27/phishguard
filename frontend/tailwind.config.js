/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        void: {
          950: '#030305',
          900: '#06070a',
          850: '#0a0c12',
          800: '#0f111a',
          750: '#151824',
          700: '#1b2030',
        },
        ember: {
          DEFAULT: '#ff4d00',
          50: '#fff5f0',
          100: '#ffe8db',
          200: '#ffd0b8',
          300: '#ffad85',
          400: '#ff7a47',
          500: '#ff4d00',
          600: '#e63e00',
          700: '#c02f00',
          800: '#942605',
          900: '#752109',
        },
        cyber: {
          red: '#ff2a4b',
          orange: '#ff5500',
          amber: '#ffb703',
          green: '#00e599',
          cyan: '#00f0ff',
          purple: '#a855f7',
        }
      },
      fontFamily: {
        display: ['Syne', 'Outfit', 'Space Grotesk', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Space Mono"', 'monospace'],
        sans: ['Outfit', 'Inter', 'sans-serif'],
      },
      boxShadow: {
        'ember-glow': '0 0 25px -5px rgba(255, 77, 0, 0.4), 0 0 10px -2px rgba(255, 77, 0, 0.2)',
        'ember-lg': '0 0 45px -5px rgba(255, 77, 0, 0.5), 0 0 20px -3px rgba(255, 77, 0, 0.3)',
        'cyan-glow': '0 0 25px -5px rgba(0, 240, 255, 0.4)',
        'red-glow': '0 0 30px -5px rgba(255, 42, 75, 0.5)',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
      },
      backgroundImage: {
        'radial-ember': 'radial-gradient(circle at 75% 30%, rgba(255, 77, 0, 0.15) 0%, transparent 60%)',
        'radial-void': 'radial-gradient(circle at 50% 50%, rgba(15, 17, 26, 0.8) 0%, #030305 100%)',
        'grid-pattern': 'linear-gradient(to right, rgba(255, 255, 255, 0.03) 1px, transparent 1px), linear-gradient(to bottom, rgba(255, 255, 255, 0.03) 1px, transparent 1px)',
      },
      animation: {
        'pulse-glow': 'pulseGlow 3s ease-in-out infinite',
        'scanline': 'scanline 8s linear infinite',
        'float': 'float 6s ease-in-out infinite',
        'radar-sweep': 'radarSweep 4s linear infinite',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { opacity: 0.8, transform: 'scale(1)' },
          '50%': { opacity: 1, transform: 'scale(1.02)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        radarSweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        }
      }
    },
  },
  plugins: [],
}
