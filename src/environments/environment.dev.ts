import { Environment } from "./environment";
import { Utils } from "../utils/Utils";

Utils.dotenvConfigs();

export const DevEnvironment: Environment = {
  db_uri: process.env.DEV_DB_URI,
  jwt_secret_key: process.env.DEV_JWT_SECRET_KEY,
  jwt_refresh_secret_key: process.env.DEV_REFRESH_TOKEN_SECRET,
  sendgrid: {
    api_key: process.env.DEV_SENDGRID_API_KEY,
    email_from: process.env.DEV_SENDGRID_SENDER_EMAIL,
  },
  gmail_auth: {
    user: process.env.DEV_GMAIL_USER,
    pass: process.env.DEV_GMAIL_PASS,
  },
  redis: {
    username: null,
    password: null,
    host: process.env.LOCAL_REDIS_HOST,
    port: parseInt(process.env.LOCAL_REDIS_PORT),
  },
};
