
import { NextResponse } from 'next/server';
import { getKnowledgeFiles, deleteKnowledgeFile, addLog } from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const files = await getKnowledgeFiles();
    return NextResponse.json(files);
  } catch (error) {
    console.error('Failed to get knowledge files:', error);
    return NextResponse.json({ message: 'Failed to get knowledge files' }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
    try {
        const { searchParams } = new URL(request.url);
        const id = searchParams.get('id');

        if (!id || !/^file_\d+$/.test(id)) {
            return NextResponse.json({ message: 'Invalid or missing file ID.' }, { status: 400 });
        }

        const files = await getKnowledgeFiles();
        const fileToDelete = files.find(f => f.id === id);

        await deleteKnowledgeFile(id);

        await addLog({
            user: 'Admin',
            action: 'Deleted Document',
            details: `File "${fileToDelete?.fileName || id}" was deleted.`,
            type: 'info',
        });

        return NextResponse.json({ message: 'File deleted successfully.' }, { status: 200 });

    } catch (error) {
        console.error('Failed to delete knowledge file:', error);
        await addLog({
            user: 'System',
            action: 'Document Deletion Failed',
            details: (error as Error).message,
            type: 'error',
        });
        return NextResponse.json({ message: 'Failed to delete knowledge file' }, { status: 500 });
    }
}
