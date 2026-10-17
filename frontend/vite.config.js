import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En développement, le front tourne sur le dev-server Vite (5173) et proxifie
// les appels /api vers le backend Flask (5000) → même origine côté navigateur,
// le cookie de session fonctionne sans CORS.
//
// En production : `npm run build` produit des fichiers statiques dans dist/ ;
// on les sert depuis Flask (un seul artefact, pas de second serveur).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:5000", changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
