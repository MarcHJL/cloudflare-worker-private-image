import JWT from '@tsndr/cloudflare-worker-jwt';
import { env } from 'cloudflare:workers';

const allowedOrigins = ['http://localhost:5001', 'http://localhost:3000', 'https://visualchaos.art'];

interface Payload {
	id: string;
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const origin = request.headers.get('Origin') || '';
		const corsHeaders = createCorsHeaders(origin, allowedOrigins);
		const token = request.headers.get('Authorization')?.split(' ')[1];

		if (!token) {
			return new Response('Unauthorized', { status: 401, headers: corsHeaders });
		}
		const payload: Payload | null = await verifyToken(token);

		if (!payload || !payload.id) {
			return new Response('Unauthorized', { status: 401, headers: corsHeaders });
		}
		return new Response('Accessing private image', { headers: corsHeaders });
	},
} satisfies ExportedHandler<Env>;

async function verifyToken(token: string) {
	const decoded = await JWT.verify(token, env.JWT_SECRET!);

	if (!decoded) {
		return null;
	}
	const { payload } = decoded;
	return payload as Payload;
}

function createCorsHeaders(origin: string, allowedOrigins: string[]) {
	const headers: Record<string, string> = {
		'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS, POST',
		'Access-Control-Allow-Headers': '*',
	};

	if (allowedOrigins.includes(origin)) {
		headers['Access-Control-Allow-Origin'] = origin;
	}

	return headers;
}
