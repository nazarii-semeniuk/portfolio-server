import supertest from 'supertest';
import application from '../../src/index';
const app = application.app;
import * as db from '../db';
const request = supertest(app);
import { faker } from '@faker-js/faker';

describe('Auth', () => {

    beforeAll(async () => {
        await db.connect();
    });

    beforeEach(async () => {
        await db.clearDatabase();
    });

    afterAll(async () => {
        await db.closeDatabase();
    });

    describe('POST /api/auth/register', () => {
        const endpoint = '/api/auth/register';

        test('should fail with invalid email', async () => {
            const response = await request.post(endpoint).send({
                email: faker.internet.email().replace('@', ''),
                password: 'password'
            });
            expect(response.status).toBe(400);
        });

        test('should fail with empty email', async () => {
            const response = await request.post(endpoint).send({
                password: 'password'
            });
            expect(response.status).toBe(400);
        });

        test('should fail with invalid password', async () => {
            const response = await request.post(endpoint).send({
                email: faker.internet.email(),
                password: 'pass'
            });
            expect(response.status).toBe(400);
        });

        test('should fail with empty password', async () => {
            const response = await request.post(endpoint).send({
                email: faker.internet.email()
            });
            expect(response.status).toBe(400);
        });

        test('should fail if email already exists', async () => {
            const email = faker.internet.email();
            const password = faker.internet.password();

            await request.post(endpoint).send({
                email,
                password
            });

            const response = await request.post(endpoint).send({
                email,
                password
            });

            expect(response.status).toBe(400);
        });


        test('should succesfully register', async () => {
            const response = await request.post(endpoint).send({
                email: faker.internet.email(),
                password: faker.internet.password()
            });
            expect(response.status).toBe(200);
        });

    });

    describe('POST /api/auth/login', () => {

        const endpoint = '/api/auth/login';

        test('should fail with invalid email', async () => {
            const response = await request.post(endpoint).send({
                email: faker.internet.email().replace('@', ''),
                password: 'password'
            });
            expect(response.status).toBe(400);
        });

        test('should fail with empty email', async () => {
            const response = await request.post(endpoint).send({
                password: 'password'
            });
            expect(response.status).toBe(400);
        });

        test('should fail with invalid password', async () => {
            const response = await request.post(endpoint).send({
                email: faker.internet.email(),
                password: 'pass'
            });
            expect(response.status).toBe(400);
        });

        test('should fail with empty password', async () => {
            const response = await request.post(endpoint).send({
                email: faker.internet.email()
            });
            expect(response.status).toBe(400);
        });

        test('should fail if email does not exist', async () => {
            const response = await request.post(endpoint).send({
                email: faker.internet.email(),
                password: faker.internet.password()
            });
            expect(response.status).toBe(400);
        });

        test('should fail if password is invalid', async () => {
            const email = faker.internet.email();
            const password = faker.internet.password();

            await request.post('/api/auth/register').send({
                email,
                password
            });

            const response = await request.post(endpoint).send({
                email,
                password: faker.internet.password()
            });

            expect(response.status).toBe(400);
        });

        test('should succesfully login', async () => {
            const email = faker.internet.email();
            const password = faker.internet.password();

            await request.post('/api/auth/register').send({
                email,
                password
            });

            const response = await request.post(endpoint).send({
                email,
                password
            });

            expect(response.status).toBe(200);
        });

    });

    describe('POST /api/auth/logout', () => {

        const endpoint = '/api/auth/logout';

        test('should succesfully logout', async () => {

            const response = await request.post(endpoint);

            expect(response.status).toBe(200);
        });

    });

    describe('POST /api/auth/refresh-token', () => {

        const endpoint = '/api/auth/refresh-token';

        test('should fail if not logged in', async () => {

            const response = await request.post(endpoint);

            expect(response.status).toBe(401);
        });

        test('should succesfully refresh token', async () => {

            const email = faker.internet.email();
            const password = faker.internet.password();

            const { header } = await request.post('/api/auth/register').send({
                email,
                password
            });

            const response = await request.post(endpoint).set('Cookie', header['set-cookie']);

            expect(response.status).toBe(200);
        });

    });

});