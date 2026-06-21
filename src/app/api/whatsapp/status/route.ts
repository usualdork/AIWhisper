import { NextResponse } from 'next/server';
import { getClientState } from '@/lib/whatsapp-client';
import { auth } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
    const session = await auth(req);
    if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const state = getClientState();
    return NextResponse.json(state);
}
