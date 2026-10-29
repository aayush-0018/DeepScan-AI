import Editor, { type OnMount } from '@monaco-editor/react';
import { useEffect, useRef } from 'react';
import type { Finding } from '../lib/api';

type MonacoEditor = Parameters<OnMount>[0];
type Monaco = Parameters<OnMount>[1];

interface Props {
  value: string;
  language: 'javascript' | 'typescript';
  onChange: (value: string) => void;
  findings: Finding[];
  focus: { line: number; nonce: number } | null;
}

export function CodeEditor({ value, language, onChange, findings, focus }: Props) {
  const editorRef = useRef<MonacoEditor | null>(null);
  const monacoRef = useRef<Monaco | null>(null);
  const decorationsRef = useRef<ReturnType<MonacoEditor['createDecorationsCollection']> | null>(null);

  const handleMount: OnMount = (editor, monaco) => {
    editorRef.current = editor;
    monacoRef.current = monaco;
    decorationsRef.current = editor.createDecorationsCollection([]);
    applyDecorations();
  };

  function applyDecorations() {
    const monaco = monacoRef.current;
    const collection = decorationsRef.current;
    if (!monaco || !collection) return;
    const decorations = findings.flatMap((f) => [
      {
        range: new monaco.Range(f.start_line, 1, f.end_line, 1),
        options: {
          isWholeLine: true,
          className: `finding-range finding-${f.severity}`,
          linesDecorationsClassName: `finding-gutter finding-gutter-${f.severity}`,
          hoverMessage: { value: `**${f.pattern}** · ${Math.round(f.confidence * 100)}% · ${f.message}` },
          overviewRuler: { color: f.severity === 'high' ? '#f43f5e' : f.severity === 'medium' ? '#f59e0b' : '#38bdf8', position: 4 },
        },
      },
      ...f.evidence_lines.map((line) => ({
        range: new monaco.Range(line, 1, line, 1),
        options: { isWholeLine: true, className: 'finding-evidence' },
      })),
    ]);
    collection.set(decorations);
  }

  useEffect(applyDecorations, [findings]);

  useEffect(() => {
    if (focus && editorRef.current) {
      editorRef.current.revealLineInCenter(focus.line);
      editorRef.current.setPosition({ lineNumber: focus.line, column: 1 });
      editorRef.current.focus();
    }
  }, [focus]);

  return (
    <Editor
      height="100%"
      theme="vs-dark"
      language={language}
      value={value}
      onChange={(v) => onChange(v ?? '')}
      onMount={handleMount}
      options={{
        fontSize: 13,
        fontFamily: 'JetBrains Mono, ui-monospace, monospace',
        minimap: { enabled: false },
        scrollBeyondLastLine: false,
        glyphMargin: false,
        lineDecorationsWidth: 6,
        renderLineHighlight: 'none',
        tabSize: 2,
        automaticLayout: true,
      }}
    />
  );
}
