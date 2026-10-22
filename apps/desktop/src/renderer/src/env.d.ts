import type { AxiomApi } from "../../preload/index";

declare module "*.css";

declare global {
  interface Window {
    axiom: AxiomApi;
  }
}

export {};
