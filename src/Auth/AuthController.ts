import { Router, Request, Response, NextFunction } from "express";
import User from './../User/UserModel';
import IController from "../types/IController";
import HttpException from "../exceptions/HttpException";
import Validator from './../utils/Validator';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { JWT_SECRET } from "../config";

class AuthController implements IController {
    public path = '/auth';
    public router = Router();

    constructor() {
        this.initializeRoutes();
    }

    private initializeRoutes() {
        this.router.post(`${this.path}/login`, this.login);
        this.router.post(`${this.path}/register`, this.register);
        this.router.post(`${this.path}/logout`, this.logout);
        this.router.post(`${this.path}/refresh-token`, this.refreshToken);
    }

    private login = async (req: Request, res: Response, next: NextFunction) => {
        const email: string = req.body.email;
        const password: string = req.body.password;

        if (!email || !password) {
            return next(new HttpException(400, 'Email and password are required'));
        }

        if(!Validator.validateEmail(email)) {
            return next(new HttpException(400, 'Email is invalid'));
        }

        if(!Validator.validatePassword(password)) {
            return next(new HttpException(400, 'Password is invalid'));
        }

        const user = await User.findOne({ email });

        if(!user) {
            return next(new HttpException(400, 'Email does not exist'));
        }

        const isPasswordValid = this.comparePasswords(password, user.password);

        if(!isPasswordValid) {
            return next(new HttpException(400, 'Password is invalid'));
        }

        const refreshToken = this.generateRefreshToken(email, password);

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            path: '/api/auth/refresh-token',
            maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year
        });

        const accessToken = this.generateAccessToken(user._id, user.role);

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            maxAge: 1000 * 60 * 10 // 10 minutes
        });

        return res.send({
            status: 200,
            message: 'Success'
        });
    }

    private register = async (req: Request, res: Response, next: NextFunction) => {
        const email: string = req.body.email;
        const password: string = req.body.password;

        if (!email || !password) {
            return next(new HttpException(400, 'Email and password are required'));
        }

        if(!Validator.validateEmail(email)) {
            return next(new HttpException(400, 'Email is invalid'));
        }

        if(!Validator.validatePassword(password)) {
            return next(new HttpException(400, 'Password is invalid'));
        }

        if(await User.findOne({ email })) {
            return next(new HttpException(400, 'Email already exists'));
        }

        const user = await User.create({
            email,
            password
        });

        const refreshToken = this.generateRefreshToken(email, password);

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            path: '/api/auth/refresh-token',
            maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year
        });

        const accessToken = this.generateAccessToken(user._id, user.role);

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            maxAge: 1000 * 60 * 10 // 10 minutes
        });

        return res.send({
            status: 200,
            message: 'Success'
        });
    }

    private logout = async (req: Request, res: Response, next: NextFunction) => {
        res.clearCookie('refreshToken');
        res.clearCookie('accessToken');
        return res.send({
            status: 200,
            message: 'Success'
        });
    }

    private refreshToken = async (req: Request, res: Response, next: NextFunction) => {
        const refreshToken = req.cookies.refreshToken;

        if(!refreshToken) {
            return next(new HttpException(401, 'Unauthorized'));
        }

        try {
            const payload = jwt.verify(refreshToken, JWT_SECRET) as { email: string, password: string };
            const user = await User.findOne({ email: payload.email });

            if(!user) {
                return next(new HttpException(401, 'Unauthorized'));
            }

            const isPasswordValid = this.comparePasswords(payload.password, user.password);

            if(!isPasswordValid) {
                return next(new HttpException(401, 'Unauthorized'));
            }

            const accessToken = this.generateAccessToken(user._id, user.role);

            res.cookie('accessToken', accessToken, {
                httpOnly: true,
                maxAge: 1000 * 60 * 10 // 10 minutes
            });

            return res.send({
                status: 200,
                message: 'Success'
            });

        } catch (error) {
            return next(new HttpException(401, 'Unauthorized'));
        }
    }

    private generateRefreshToken(email: string, password: string): string {
        const payload = {
            email,
            password
        }
        const token = jwt.sign(payload, JWT_SECRET);
        return token;
    }

    private generateAccessToken(id: string, role: string): string {
        const payload = {
            id,
            role
        }
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '10m' });
        return token;
    }

    private comparePasswords(password: string, userPassword: string): boolean {
        return bcrypt.compareSync(password, userPassword);
    }

}

export default AuthController;