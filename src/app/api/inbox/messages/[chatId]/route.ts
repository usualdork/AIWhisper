
import { NextResponse } from 'next/server';
import { getMessages } from '@/lib/db';
import { requireSession } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export async function GET(
  request: Request,
  { params }: { params: { chatId: string } }
) {
  try {
    await requireSession(request);
    // `params` is now an async proxy in Next.js 15 — await it before reading
    const { chatId } = await params;
    if (!chatId) {
      return NextResponse.json({ message: 'chatId is required' }, { status: 400 });
    }
    const messages = await getMessages(chatId);
    return NextResponse.json(messages);
  } catch (error) {
    console.error('Failed to fetch messages:', error);
    return NextResponse.json({ message: 'Failed to fetch messages' }, { status: 500 });
  }
}
