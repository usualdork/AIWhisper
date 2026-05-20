
import { NextResponse } from 'next/server';
import { sendMessage } from '@/lib/whatsapp-client';

export async function POST(request: Request) {
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');
  const allowedOrigin = process.env.APP_ORIGIN;
  if (!allowedOrigin) {
    return NextResponse.json({ success: false, message: 'Server misconfiguration: APP_ORIGIN not set' }, { status: 500 });
  }
  if (origin !== allowedOrigin && (!referer || !referer.startsWith(allowedOrigin))) {
    return NextResponse.json({ success: false, message: 'Forbidden' }, { status: 403 });
  }
  try {
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
