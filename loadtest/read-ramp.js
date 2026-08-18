import http from 'k6/http';
import { check } from 'k6';
import { Trend, Rate } from 'k6/metrics';

const errorRate = new Rate('errors');
const readLatency = new Trend('read_latency');

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8001';
const API_KEY = __ENV.API_KEY || 'dev-key-changeme-in-production';

export const options = {
  stages: [
    { duration: '30s', target: 10 },
    { duration: '30s', target: 50 },
    { duration: '30s', target: 100 },
    { duration: '30s', target: 200 },
    { duration: '30s', target: 400 },
    { duration: '20s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<2000', 'max<10000'],
    errors: ['rate<0.01'],
  },
};

export default function () {
  const params = {
    headers: { 'X-API-Key': API_KEY },
    tags: { endpoint: 'list_assets' },
  };

  const res = http.get(`${BASE_URL}/assets`, params);

  const ok = check(res, {
    'status 200': (r) => r.status === 200,
  });

  errorRate.add(!ok);
  readLatency.add(res.timings.duration);
}
