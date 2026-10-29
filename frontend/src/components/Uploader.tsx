import { useRef, useState, type DragEvent } from 'react';

const ACCEPT = '.js,.mjs,.cjs,.jsx,.ts,.mts,.cts,.tsx,.zip';

interface Props {
  files: File[];
  onChange: (files: File[]) => void;
}

export function Uploader({ files, onChange }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  function add(list: FileList | null) {
    if (!list) return;
    const incoming = Array.from(list);
    const names = new Set(files.map((f) => f.name));
    onChange([...files, ...incoming.filter((f) => !names.has(f.name))]);
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    add(e.dataTransfer.files);
  }

  return (
    <div className="flex h-full flex-col gap-4 p-5">
      <div
        role="button"
        tabIndex={0}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`flex flex-1 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed transition ${
          dragging ? 'border-cyan-400 bg-cyan-400/5' : 'border-slate-700 hover:border-slate-500'
        }`}
      >
        <svg viewBox="0 0 24 24" className="mb-3 h-10 w-10 text-slate-500" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M12 16V4m0 0-4 4m4-4 4 4M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <p className="text-sm font-medium text-slate-300">Drop JS/TS files or a .zip of your project</p>
        <p className="mt-1 text-xs text-slate-500">node_modules, dist, build and *.min.js are skipped automatically</p>
        <input
          ref={inputRef}
          type="file"
          multiple
          accept={ACCEPT}
          className="hidden"
          onChange={(e) => {
            add(e.target.files);
            e.target.value = '';
          }}
        />
      </div>

      {files.length > 0 && (
        <ul className="max-h-56 space-y-1 overflow-auto">
          {files.map((f) => (
            <li key={f.name} className="flex items-center justify-between rounded-md bg-slate-900 px-3 py-2 text-sm">
              <span className="truncate font-mono text-slate-300">{f.name}</span>
              <span className="ml-3 flex items-center gap-3 text-xs text-slate-500">
                {(f.size / 1024).toFixed(1)} KB
                <button
                  type="button"
                  aria-label={`Remove ${f.name}`}
                  className="text-slate-500 hover:text-rose-400"
                  onClick={() => onChange(files.filter((x) => x !== f))}
                >
                  ✕
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
