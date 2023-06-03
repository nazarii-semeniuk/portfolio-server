import request from 'supertest';
import app from '../../src/index';

describe('User', () => {

    test('GET /user/:id', async () => {
        const response = await request(app.app).get('/api/user/10');
        expect(response.status).toBe(200);
    });

});