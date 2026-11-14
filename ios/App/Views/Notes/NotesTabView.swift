import PrivateSpaceKit
import SwiftUI

struct NotesTabView: View {
    @Bindable var store: VaultStore
    let onInspectCipher: (String) -> Void
    @Environment(\.colorScheme) private var colorScheme

    @State private var searchQuery: String = ""
    @State private var activeFilter: NoteListFilter = .all
    @State private var selectedTag: String?
    @State private var sortMode: NoteSortMode = .updated
    @State private var activeNote: NoteItem?

    var body: some View {
        NavigationStack {
            let notes = store.filteredNotes(
                query: searchQuery,
                filter: activeFilter,
                tag: selectedTag,
                sort: sortMode
            )

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // Filter Chips + Tag Pills
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(NoteListFilter.allCases) { f in
                                FilterChipButton(
                                    title: f.rawValue,
                                    icon: iconForFilter(f),
                                    isSelected: selectedTag == nil && activeFilter == f
                                ) {
                                    selectedTag = nil
                                    activeFilter = f
                                }
                            }

                            ForEach(store.allNoteTags, id: \.self) { tag in
                                FilterChipButton(
                                    title: "#\(tag)",
                                    icon: nil,
                                    isSelected: selectedTag == tag
                                ) {
                                    selectedTag = (selectedTag == tag) ? nil : tag
                                }
                            }
                        }
                    }

                    if notes.isEmpty {
                        ContentUnavailableView(
                            "暂无加密文本笔记",
                            systemImage: "doc.text.magnifyingglass",
                            description: Text("所有笔记标题、正文与标签均通过独立 HKDF-SHA256 子密钥 + AES-256-GCM 认证加密")
                        )
                        .padding(.vertical, 44)
                    } else {
                        VStack(spacing: 10) {
                            ForEach(notes) { note in
                                Button {
                                    activeNote = note
                                } label: {
                                    NoteCardRow(note: note)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(MineralPineTheme.pageBackground(for: colorScheme))
            .navigationTitle("加密笔记")
            .searchable(text: $searchQuery, prompt: "全文检索加密笔记标题、正文或标签")
            .refreshable {
                await store.syncDelta()
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Menu {
                        Picker("排序方式", selection: $sortMode) {
                            ForEach(NoteSortMode.allCases) { mode in
                                Text(mode.rawValue).tag(mode)
                            }
                        }
                    } label: {
                        Label("排序", systemImage: "arrow.up.arrow.down.circle")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task {
                            if let created = await store.createNote(
                                CreateNoteRequest(
                                    title: "",
                                    content: "",
                                    tags: selectedTag.map { [$0] } ?? [],
                                    format: .markdown
                                )
                            ) {
                                activeNote = created
                            }
                        }
                    } label: {
                        Image(systemName: "square.and.pencil")
                            .font(.title3)
                    }
                }
            }
            .navigationDestination(item: $activeNote) { note in
                let liveNote = store.snapshot.notes[note.id] ?? note
                NoteEditorDetailView(
                    note: liveNote,
                    store: store,
                    onInspectCipher: { onInspectCipher(liveNote.id) }
                )
            }
        }
    }

    private func iconForFilter(_ f: NoteListFilter) -> String {
        switch f {
        case .all: return "tray.full"
        case .pinned: return "pin.fill"
        case .archived: return "archivebox"
        case .trash: return "trash"
        }
    }
}

private struct NoteCardRow: View {
    let note: NoteItem
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(note.title.isEmpty ? "无标题加密笔记" : note.title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer()
                if note.isPinned {
                    Image(systemName: "pin.fill")
                        .font(.caption2)
                        .foregroundStyle(MineralPineTheme.amber)
                }
                Text(VaultFormatters.shortDate(note.updatedAt))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            if !note.excerpt.isEmpty {
                Text(note.excerpt)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
            }

            HStack(spacing: 6) {
                ForEach(note.tags.prefix(3), id: \.self) { tag in
                    Text("#\(tag)")
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(
                            MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.11),
                            in: Capsule()
                        )
                }
                Spacer()
                Text("Rev #\(note.revision) · \(VaultFormatters.formatBytes(note.byteSize))")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .background(MineralPineTheme.cardBackground(for: colorScheme), in: RoundedRectangle(cornerRadius: 15))
        .overlay(
            RoundedRectangle(cornerRadius: 15)
                .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
        )
    }
}

// MARK: - Native Markdown & Checklist Note Editor

struct NoteEditorDetailView: View {
    let note: NoteItem
    @Bindable var store: VaultStore
    let onInspectCipher: () -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme

    @State private var title: String = ""
    @State private var content: String = ""
    @State private var tagsText: String = ""
    @State private var previewMode = false
    @State private var hasUnsavedChanges = false

    var body: some View {
        VStack(spacing: 0) {
            Picker("视图模式", selection: $previewMode) {
                Text("Markdown 编辑").tag(false)
                Text("交互预览").tag(true)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            if previewMode {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(title.isEmpty ? "无标题笔记" : title)
                            .font(.title2.weight(.bold))

                        InteractiveMarkdownPreview(content: $content) {
                            hasUnsavedChanges = true
                            saveChanges()
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(18)
                }
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    TextField("笔记标题", text: $title)
                        .font(.title3.weight(.bold))
                        .padding(.horizontal, 16)
                        .padding(.top, 8)
                        .onChange(of: title) { _, _ in hasUnsavedChanges = true }

                    TextField("标签（用逗号分隔，例如：架构, 私密）", text: $tagsText)
                        .font(.caption)
                        .padding(.horizontal, 16)
                        .onChange(of: tagsText) { _, _ in hasUnsavedChanges = true }

                    Divider()

                    // Quick Markdown Insert Bar
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 10) {
                            Button("**粗体**") { content += "**粗体**"; hasUnsavedChanges = true }
                            Button("待办 [ ]") { content += "\n- [ ] 待办事项"; hasUnsavedChanges = true }
                            Button("`代码`") { content += " `code` "; hasUnsavedChanges = true }
                            Button("## 标题") { content += "\n## 小节标题\n"; hasUnsavedChanges = true }
                            Button("> 引用") { content += "\n> 引用说明\n"; hasUnsavedChanges = true }
                        }
                        .font(.caption.weight(.semibold))
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .padding(.horizontal, 16)
                    }

                    TextEditor(text: $content)
                        .font(.system(.body, design: .default))
                        .scrollContentBackground(.hidden)
                        .padding(.horizontal, 12)
                        .onChange(of: content) { _, _ in hasUnsavedChanges = true }
                }
            }
        }
        .background(MineralPineTheme.pageBackground(for: colorScheme))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                if hasUnsavedChanges {
                    Button("保存") {
                        saveChanges()
                    }
                    .fontWeight(.semibold)
                }

                Menu {
                    Button {
                        Task {
                            await store.updateNote(
                                id: note.id,
                                patch: UpdateNoteRequest(isPinned: !note.isPinned)
                            )
                        }
                    } label: {
                        Label(note.isPinned ? "取消置顶" : "置顶笔记", systemImage: "pin")
                    }

                    Button {
                        Task {
                            await store.updateNote(
                                id: note.id,
                                patch: UpdateNoteRequest(isArchived: !note.isArchived)
                            )
                        }
                    } label: {
                        Label(note.isArchived ? "移出归档" : "归档笔记", systemImage: "archivebox")
                    }

                    Button {
                        onInspectCipher()
                    } label: {
                        Label("透视 AES-256-GCM 密文信封", systemImage: "lock.doc")
                    }

                    Divider()

                    Button(role: .destructive) {
                        Task {
                            if note.isTrashed {
                                await store.deleteNotePermanently(id: note.id)
                            } else {
                                await store.updateNote(
                                    id: note.id,
                                    patch: UpdateNoteRequest(isTrashed: true)
                                )
                            }
                            dismiss()
                        }
                    } label: {
                        Label(note.isTrashed ? "彻底销毁密文" : "移入回收站", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .onAppear {
            title = note.title
            content = note.content
            tagsText = note.tags.joined(separator: ", ")
            hasUnsavedChanges = false
        }
        .onDisappear {
            if hasUnsavedChanges {
                saveChanges()
            }
        }
    }

    private func saveChanges() {
        let tags = tagsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        hasUnsavedChanges = false
        Task {
            await store.updateNote(
                id: note.id,
                patch: UpdateNoteRequest(
                    title: title,
                    content: content,
                    tags: tags
                )
            )
        }
    }
}

private struct InteractiveMarkdownPreview: View {
    @Binding var content: String
    let onToggled: () -> Void

    var body: some View {
        let lines = content.components(separatedBy: "\n")
        VStack(alignment: .leading, spacing: 8) {
            ForEach(Array(lines.enumerated()), id: \.offset) { idx, line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("- [ ] ") || trimmed.hasPrefix("- [x] ") || trimmed.hasPrefix("- [X] ") {
                    let checked = !trimmed.hasPrefix("- [ ] ")
                    let labelText = String(trimmed.dropFirst(6))
                    Button {
                        toggleChecklistLine(at: idx, currentlyChecked: checked)
                    } label: {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: checked ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(checked ? MineralPineTheme.accent : .secondary)
                            Text(labelText)
                                .strikethrough(checked)
                                .foregroundStyle(checked ? .secondary : .primary)
                                .multilineTextAlignment(.leading)
                        }
                    }
                    .buttonStyle(.plain)
                } else if let attributed = try? AttributedString(markdown: line) {
                    Text(attributed)
                        .font(.body)
                } else {
                    Text(line)
                        .font(.body)
                }
            }
        }
    }

    private func toggleChecklistLine(at lineIndex: Int, currentlyChecked: Bool) {
        var lines = content.components(separatedBy: "\n")
        guard lineIndex < lines.count else { return }
        if currentlyChecked {
            lines[lineIndex] = lines[lineIndex]
                .replacingOccurrences(of: "- [x] ", with: "- [ ] ")
                .replacingOccurrences(of: "- [X] ", with: "- [ ] ")
        } else {
            lines[lineIndex] = lines[lineIndex]
                .replacingOccurrences(of: "- [ ] ", with: "- [x] ")
        }
        content = lines.joined(separator: "\n")
        onToggled()
    }
}
