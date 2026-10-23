import type { HexScryApi } from "../../preload/index";

declare module "*.css";

declare global {
  interface Window {
    hexscry: HexScryApi;
  }
}

export {};
