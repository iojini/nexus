/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        gold: {
          50: '#FFFDF7',
          100: '#FEF9E7',
          200: '#FDF0C4',
          300: '#F4E4BA',
          400: '#E5C76B',
          500: '#D4AF37',
          600: '#B8960B',
          700: '#8B7209',
          800: '#5C4B06',
          900: '#2E2603',
        },
        dark: {
          50: '#78716C',
          100: '#57534E',
          200: '#44403C',
          300: '#292524',
          400: '#1C1917',
          500: '#171412',
          600: '#120F0D',
          700: '#0C0A09',
          800: '#080606',
          900: '#030202',
        }
      },
      fontFamily: {
        'display': ['Outfit', 'sans-serif'],
        'body': ['Inter', 'sans-serif'],
      },
      backgroundImage: {
        'gold-gradient': 'linear-gradient(135deg, #D4AF37 0%, #F4E4BA 50%, #D4AF37 100%)',
        'gold-subtle': 'linear-gradient(135deg, #D4AF37 0%, #B8960B 100%)',
        'dark-gradient': 'linear-gradient(180deg, #0C0A09 0%, #1C1917 100%)',
        'card-gradient': 'linear-gradient(180deg, rgba(212,175,55,0.03) 0%, rgba(0,0,0,0) 100%)',
      },
      boxShadow: {
        'gold': '0 0 20px rgba(212,175,55,0.15)',
        'gold-lg': '0 0 40px rgba(212,175,55,0.2)',
        'inner-gold': 'inset 0 1px 0 0 rgba(212,175,55,0.1)',
      }
    },
  },
  plugins: [],
}
