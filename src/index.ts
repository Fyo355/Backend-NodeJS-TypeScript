import { Server } from "./server";

let server = new Server().app;
let port = parseInt(process.env.PORT) || 3000;
const hostname = "127.0.0.1";

server.listen(port, hostname, () => {
  console.log(`Server is running at port ${port}`);
});
