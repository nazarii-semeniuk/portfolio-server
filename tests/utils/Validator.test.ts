import Validator from "../../src/utils/Validator";

describe('Validator', () => {

    describe('validateEmail', () => {

        test("should fail if email don't have @", () => {
            expect(Validator.validateEmail('testtest.com')).toBeFalsy();
        });

        test("should fail if email don't have .", () => {
            expect(Validator.validateEmail('test@testcom')).toBeFalsy();
        });

        test("should fail if email don't have domain", () => {
            expect(Validator.validateEmail('test@test.')).toBeFalsy();
        });

        test("should fail if email don't have username", () => {
            expect(Validator.validateEmail('@test.com')).toBeFalsy();
        });

        test("should fail if email is empty", () => {
            expect(Validator.validateEmail('')).toBeFalsy();
        });

    });

    describe('validatePassword', () => {

        test("should fail if password is less than 8 characters", () => {
            expect(Validator.validatePassword('pass')).toBeFalsy();
        });

        test("should fail if password is empty", () => {
            expect(Validator.validatePassword('')).toBeFalsy();
        });

    });

});