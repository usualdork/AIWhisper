import { NextResponse } from 'next/server';
import { getClientState } from '@/lib/whatsapp-client';
import { auth } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
    const session = await auth();
    if (!session?.user) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const state = getClientState();

    // Only expose the QR code to the user that initiated the pairing
    if (state.qr && (state as any).initiatorUserId && session.user.id !== (state as any).initiatorUserId) {
        return NextResponse.json({ ...state, qr: null });
    }

    return NextResponse.json(state);
}
