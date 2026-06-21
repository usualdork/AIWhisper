
import { NextResponse } from 'next/server';
import { sendMessage } from '@/lib/whatsapp-client';
import { getSession } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    const session = await getSession();
    if (!session) {
      return NextResponse.json({ success: false, message: 'Unauthorized' }, { status: 401 });
    }
    const { to, text } = await request.json();
    if (!to || !text) {
      return NextResponse.json({ success: false, message: 'Missing "to" or "text" field' }, { status: 400 });
    }
    const result = await sendMessage(to, text);
    return NextResponse.json({ success: true, data: result });
  } catch (error: any) {
    console.error("Failed to send message", error);
    return NextResponse.json({ success: false, message: error.message || 'Failed to send message' }, { status: 500 });
  }
}
