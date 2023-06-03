class Validator {

    static validateEmail(email: string): boolean {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    static validatePassword(password: string): boolean {
        return password.length >= 8;
    }

}

export default Validator;