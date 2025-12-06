import compression from "compression";
import cors from "cors";
import express, { Application, NextFunction, Request, Response } from "express";
import mongoSanitize from "express-mongo-sanitize";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import hpp from "hpp";
import sanitizeHtml from "sanitize-html";
import config from "../config";
import sendResponse from "../utils/sendResponse";

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, try again later.",
});

export const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many login attempts, try again later.",
});

const allowedMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

export const applySecurity = (app: Application) => {
  app.disable("x-powered-by");

  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: true,
    })
  );
  app.use(helmet.frameguard({ action: "deny" }));
  app.use(helmet.noSniff());

  // CORS
  const allowedOrigins = (config.allowedOrigins || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
          return callback(null, true);
        }
        return callback(new Error("Not allowed by CORS"));
      },
      credentials: true,
      methods: allowedMethods,
      allowedHeaders: ["Content-Type", "Authorization", "Accept"],
    })
  );

  // Prevent HTTP Parameter Pollution
  app.use(hpp());

  // Compression
  app.use(compression());

  // Body parsers with size limit
  app.use(express.json({ limit: "10kb" }));
  app.use(express.urlencoded({ extended: true, limit: "10kb" }));

  // Mongo sanitize
  app.use(mongoSanitize());

  // Input sanitizer (XSS protection)
  app.use((req: Request, _res: Response, next: NextFunction) => {
    if (req.body && typeof req.body === "object") {
      const clean = (obj: any) => {
        for (const key in obj) {
          const val = obj[key];
          if (typeof val === "string") {
            obj[key] = sanitizeHtml(val, {
              allowedTags: [],
              allowedAttributes: {},
            });
          } else if (val && typeof val === "object" && !Array.isArray(val)) {
            clean(val);
          } else if (Array.isArray(val)) {
            obj[key] = val.map((it) =>
              typeof it === "string"
                ? sanitizeHtml(it, { allowedTags: [], allowedAttributes: {} })
                : it
            );
          }
        }
      };
      clean(req.body);
    }
    next();
  });

  app.use(globalLimiter);

  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!allowedMethods.includes(req.method)) {
      res.status(405).json({ message: "Method not allowed" });
      return;
    }
    next();
  });

  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error("Security Error:", err);

    const statusCode = err?.statusCode || err?.status || 500;
    const message =
      statusCode < 500
        ? err?.message || "Bad request"
        : "Internal server error (secure mode)";

    try {
      sendResponse(res, {
        statusCode,
        success: false,
        message,
      });
    } catch {
      res.status(statusCode).json({ success: false, message });
    }
  });
};
