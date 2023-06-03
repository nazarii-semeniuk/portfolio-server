import * as mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import IUser from './IUser';
import Role from './Role';

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstName: { type: String },
    lastName: { type: String },
    photo: { type: String },
    role: { type: String, enum: Role, default: Role.User },
    created_at: { type: Date, default: new Date() }
});

const saltRounds = 8;

UserSchema.pre('save', async function(next) {
    const user = this;
    if(user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, saltRounds);
    }
    next();
});

const UserModel = mongoose.model<IUser & mongoose.Document>('User', UserSchema);

export default UserModel;