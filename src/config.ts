import { config } from "dotenv";
import { cleanEnv, port, str } from "envalid";

config();

const env = cleanEnv(process.env, {
    PORT: port(),
    JWT_SECRET: str()
});

export const PORT: number = env.PORT;
export const JWT_SECRET: string = env.JWT_SECRET;
export const NODE_ENV: string = process.env.NODE_ENV || 'development';