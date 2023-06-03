import Role from './Role';

interface IUser {
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
    photo?: string;
    role: Role;
}

export default IUser;