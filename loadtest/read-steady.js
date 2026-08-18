import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8001';
const API_KEY = __ENV.API_KEY || 'dev-key-changeme-in-production';

export const options = {
  stages: [
    { duration: '60s', target: 300 },
    { duration: '10s', target: 0 },
  ],
};

export default function () {
  const res = http.get(`${BASE_URL}/assets`, {
    headers: { 'X-API-Key': API_KEY },
    timeout: '10s',
  });
  check(res, { 'status 200': (r) => r.status === 200 });
}
