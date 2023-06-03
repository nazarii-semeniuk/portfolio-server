import App from './app';
import { PORT, NODE_ENV } from './config';

import AuthController from './Auth/AuthController';
import UserController from './User/UserController';

const app = new App(
    [
        new AuthController(),
        new UserController()
    ],
    PORT
);

if(NODE_ENV !== 'test') {
    app.listen();
}

export default app;