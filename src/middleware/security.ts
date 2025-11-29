import compression from "compression";
import { Application, NextFunction, Request, Response } from "express";
import mongoSanitize from "express-mongo-sanitize";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import hpp from "hpp";
import sendResponse from "../utils/sendResponse";

export const applySecurity = (app: Application) => {
  // 1. Helmet
  app.use(
    helmet({
      contentSecurityPolicy: false,
    })
  );

  // 3. Prevent HTTP Parameter Pollution
  app.use(hpp());
  app.use(compression()); //for faster response times and performance

  // 4. Rate Limiting
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 150,
      standardHeaders: true,
      legacyHeaders: false,
      message: "Too many requests, try again later.",
    })
  );

  // 5. Mongo Sanitize
  app.use(mongoSanitize());

  // 6. Global Security Error Handler
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error("Security Error:", err);

    const statusCode = err.statusCode || err.status || 500;

    sendResponse(res, {
      statusCode,
      success: false,
      message:
        statusCode < 500 ? err.message : "Internal server error (secure mode)",
    });
  });
};
