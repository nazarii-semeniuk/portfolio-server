import { Router, Request, Response } from "express";
import IController from "../types/IController";

class UserController implements IController {
    public path = '/user';
    public router = Router();

    constructor() {
        this.initializeRoutes();
    }

    private initializeRoutes() {
        this.router.get(`${this.path}/:id`, this.getUser);
    }

    private getUser = (req: Request, res: Response) => {
        res.send('user');
    }
}

export default UserController;