import http from "http";
import mongoose from "mongoose";
import { Server } from "socket.io";
import app from "./app";
import config from "./config";
import { initNotificationSocket } from "./socket/notification.service";

async function main() {
  try {
    await mongoose.connect(config.mongodbUrl as string);
    console.log("MongoDB connected successfully");
    const httpServer = http.createServer(app);

    const io = new Server(httpServer, {
      cors: {
        origin: "*", 
        methods: ["GET", "POST"],
      },
    });

    io.on("connection", (socket) => {
      console.log("Client connected:", socket.id);
      socket.on("joinRoom", (userId) => socket.join(userId));
    });

    initNotificationSocket(io);

    httpServer.listen(config.port, () => {
      console.log(`Server running on port ${config.port}`);
    });
  } catch (error) {
    console.error("Server failed to start:", error);
  }
}

main();
