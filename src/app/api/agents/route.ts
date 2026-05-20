
import { NextResponse } from 'next/server';
import { headers, cookies } from 'next/headers';
import { addAgent, getAgents, addLog } from '@/lib/db';
import type { Agent } from '@/types';

async function requireAuth(): Promise<{ ok: true; user: string } | { ok: false; response: NextResponse }> {
  try {
    // Try NextAuth/Auth.js style session via JWT first if configured
    const { getToken } = await import('next-auth/jwt').catch(() => ({ getToken: null as any }));
    if (getToken) {
      // next-auth getToken needs a Request; reconstruct minimal req from headers/cookies
      const hdrs = headers();
      const cks = cookies();
      const req: any = {
        headers: Object.fromEntries(hdrs.entries()),
        cookies: Object.fromEntries(cks.getAll().map(c => [c.name, c.value])),
      };
      const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });
      if (token && (token.sub || (token as any).email)) {
        return { ok: true, user: String((token as any).email || token.sub) };
      }
    }
  } catch {}
  return { ok: false, response: NextResponse.json({ message: 'Unauthorized' }, { status: 401 }) };
}

export async function GET() {
  const auth = await requireAuth();
  if (!auth.ok) return auth.response;
  try {
    const agents = await getAgents();
    return NextResponse.json(agents);
  } catch (error) {
    console.error('Failed to get agents:', error);
    return NextResponse.json({ message: 'Failed to get agents' }, { status: 500 });
  }
}

export async function POST(request: Request) {
  const auth = await requireAuth();
  const hdrs = headers();
  const ip = hdrs.get('x-forwarded-for') || hdrs.get('x-real-ip') || 'unknown';
  if (!auth.ok) return auth.response;
  try {
    const body = await request.json() as Partial<Omit<Agent, 'id'>>;
    if (!body.mode) body.mode = 'rule';

    // Basic validation
    if (!body.name) {
      return NextResponse.json({ message: 'Agent name is required.' }, { status: 400 });
    }

    // Only validate rules for rule-based agents
    if (body.mode === 'rule' && (!body.rules || body.rules.length === 0)) {
      return NextResponse.json({ message: 'At least one rule is required for rule-based agents.' }, { status: 400 });
    }

    // For AI mode, validate AI settings
    if (body.mode === 'ai') {
      console.log('Processing AI mode agent:', body);
      
      // Ensure aiSettings exists
      if (!body.aiSettings) {
        return NextResponse.json({ message: 'AI settings are required for AI mode agents.' }, { status: 400 });
      }
      
      // Ensure rules array exists for AI mode to satisfy type shape
      if (!('rules' in body)) {
        (body as any).rules = [];
      }
    }

    const newAgent = await addAgent(body as any);
    
      ip,
    await addLog({
      user: auth.user,
      action: 'Created Agent',
      details: `New agent named "${newAgent.name}" was created.`,
      type: 'success',
    });

    return NextResponse.json(newAgent, { status: 201 });
  } catch (error) {
        user: auth.user,
        ip,
    await addLog({
        user: 'System',
        action: 'Agent Creation Failed',
        details: (error as Error).message,
        type: 'error',
    });
    return NextResponse.json({ message: 'Failed to create agent' }, { status: 500 });
  }
}
