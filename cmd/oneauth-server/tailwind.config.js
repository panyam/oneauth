// Tailwind config for the reference server's templates. `make server-css`
// regenerates static/app.css from it; the CSS is committed and embedded, so
// the server loads no third-party script.
module.exports = {
  content: ["./templates/*.html"],
  theme: { extend: {} },
  plugins: [],
};
