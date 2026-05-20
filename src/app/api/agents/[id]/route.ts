import { NextResponse } from 'next/server';
import { updateAgent, deleteAgent, getAgent, addLog } from '@/lib/db';
import type { Agent } from '@/types';

export async function GET(_req: Request, ctx: { params: { id: string } | Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const agent = await getAgent(id);
    if (!agent) return NextResponse.json({ message: 'Not found' }, { status: 404 });
    return NextResponse.json(agent);
  } catch (error) {
    console.error('Failed to fetch agent:', error);
    return NextResponse.json({ message: 'Failed' }, { status: 500 });
  }
}

export async function PATCH(request: Request, ctx: { params: { id: string } | Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const body = (await request.json()) as Partial<Omit<Agent, 'id'>>;
    
    // For AI mode, validate and ensure proper structure
    if (body.mode === 'ai') {
      
      // Ensure aiSettings exists
      if (!body.aiSettings) {
        return NextResponse.json({ message: 'AI settings are required for AI mode agents.' }, { status: 400 });
      }
      
      // Ensure rules array exists for AI mode to satisfy type shape
      if (!('rules' in body)) {
        (body as any).rules = [];
      }
    }
    await updateAgent(id, body);
    await addLog({
      user: 'Admin',
      action: 'Updated Agent',
      details: 'Agent updated.',
      type: 'info',
    });
    const updated = await getAgent(id);
    return NextResponse.json(updated);
  } catch (error) {
    console.error('Failed to update agent:', error);
    return NextResponse.json({ message: 'Failed to update agent' }, { status: 500 });
  }
}

export async function DELETE(_req: Request, ctx: { params: { id: string } | Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    await deleteAgent(id);
    await addLog({
      user: 'Admin',
      action: 'Deleted Agent',
      details: 'Agent deleted.',
      type: 'warning',
    });
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Failed to delete agent:', error);
    return NextResponse.json({ message: 'Failed to delete agent' }, { status: 500 });
  }
}
