/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        graphite: {
          950: "#0c0e12",
          900: "#12151c",
          800: "#1a1f2a",
          700: "#252b38",
        },
        accent: {
          danger: "#e85d4c",
          warn: "#e09b3d",
        },
      },
    },
  },
  plugins: [],
};
