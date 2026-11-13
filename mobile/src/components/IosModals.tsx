import React, { useEffect, useState } from 'react';
import {
  Image,
  Modal,
  ScrollView,
  Switch,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import type {
  CipherEnvelopeInspection,
  CreatePasswordRequest,
  MediaItem,
  NoteItem,
  PasswordCategory,
  PasswordCustomField,
  PasswordItem,
  UpdateMediaRequest,
  UpdateNoteRequest,
  UpdatePasswordRequest,
} from '@shared/types';
import {
  formatMobileBytes,
  formatMobileDuration,
  formatMobileShortTime,
  type IosThemeTokens,
} from '../iosTheme';
import {
  copyTextWithClipboard,
  IosStreamingVideoSurface,
  IosTotpRing,
} from '../iosNativeBridge';
import { parseMobilePasswordCsv, type PrivateSpaceMobileClient } from '../syncClient';

export const PASSWORD_CATEGORIES: Array<{ id: PasswordCategory; label: string }> = [
  { id: 'login', label: '网站登录' },
  { id: 'finance', label: '金融支付' },
  { id: 'work', label: '办公协作' },
  { id: 'dev', label: '开发凭据' },
  { id: 'social', label: '社交账号' },
  { id: 'server', label: '服务器运维' },
  { id: 'other', label: '其他凭据' },
];

function SheetHeader(props: {
  title: string;
  leftLabel?: string;
  rightLabel?: string;
  onLeft: () => void;
  onRight?: () => void;
  rightDisabled?: boolean;
  theme: IosThemeTokens;
}): React.JSX.Element {
  return (
    <View
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 16,
        paddingVertical: 13,
        borderBottomWidth: 1,
        borderBottomColor: props.theme.border,
      }}
    >
      <TouchableOpacity
        onPress={props.onLeft}
        style={{ flexShrink: 0 }}
        testID="sheet-close-btn"
      >
        <Text
          style={{ fontSize: 14, fontWeight: '600', color: props.theme.textSecondary }}
          numberOfLines={1}
        >
          {props.leftLabel ?? '关闭'}
        </Text>
      </TouchableOpacity>
      <Text
        style={{
          flex: 1,
          textAlign: 'center',
          marginHorizontal: 10,
          fontSize: 15,
          fontWeight: '700',
          color: props.theme.textPrimary,
        }}
        numberOfLines={1}
      >
        {props.title}
      </Text>
      {props.onRight ? (
        <TouchableOpacity
          onPress={props.onRight}
          disabled={props.rightDisabled}
          style={{ flexShrink: 0 }}
          testID="sheet-confirm-btn"
        >
          <Text
            style={{ fontSize: 14, fontWeight: '700', color: props.theme.accent }}
            numberOfLines={1}
          >
            {props.rightLabel ?? '保存'}
          </Text>
        </TouchableOpacity>
      ) : (
        <View style={{ width: 36, flexShrink: 0 }} />
      )}
    </View>
  );
}

// ==================== 1. Password Detail Bottom Sheet ====================

export function IosPasswordDetailModal(props: {
  item: PasswordItem | null;
  tick: number;
  client: PrivateSpaceMobileClient;
  theme: IosThemeTokens;
  onClose: () => void;
  onEdit: (item: PasswordItem) => void;
  onUpdate: (id: string, patch: UpdatePasswordRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onInspectCipher: (id: string) => void;
  onToast: (msg: string) => void;
}): React.JSX.Element | null {
  const [showSecret, setShowSecret] = useState(false);
  const [revealedIds, setRevealedIds] = useState<Record<string, boolean>>({});

  if (!props.item) return null;
  const item = props.item;
  const totp = item.totpSecret ? props.client.computeTotp(item.totpSecret, props.tick) : null;
  const entropy = props.client.evaluateEntropy(item.password);

  return (
    <Modal visible transparent animationType="slide" onRequestClose={props.onClose}>
      <View
        style={{
          maxHeight: '92%',
          backgroundColor: props.theme.bgPage,
          borderTopLeftRadius: 22,
          borderTopRightRadius: 22,
          overflow: 'hidden',
          borderTopWidth: 1,
          borderTopColor: props.theme.border,
        }}
      >
        <SheetHeader
          title={item.title}
          leftLabel="返回"
          rightLabel="编辑"
          onLeft={props.onClose}
          onRight={() => props.onEdit(item)}
          theme={props.theme}
        />

        <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
          <View
            style={{
              backgroundColor: props.theme.bgCard,
              borderRadius: 15,
              padding: 14,
              gap: 12,
              borderWidth: 1,
              borderColor: props.theme.border,
            }}
          >
            {item.username ? (
              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <View style={{ flex: 1 }}>
                  <Text style={{ fontSize: 11, color: props.theme.textSecondary }}>
                    账号 / 用户名
                  </Text>
                  <Text
                    style={{ fontSize: 14, fontWeight: '600', color: props.theme.textPrimary, marginTop: 2 }}
                    selectable
                  >
                    {item.username}
                  </Text>
                </View>
                <TouchableOpacity
                  onPress={async () => {
                    await copyTextWithClipboard(item.username);
                    props.onToast('用户名已复制');
                  }}
                  style={{
                    paddingHorizontal: 10,
                    paddingVertical: 5,
                    borderRadius: 8,
                    backgroundColor: props.theme.bgSubtle,
                  }}
                >
                  <Text style={{ fontSize: 12, fontWeight: '600', color: props.theme.accent }}>
                    复制
                  </Text>
                </TouchableOpacity>
              </View>
            ) : null}

            <View style={{ gap: 6 }}>
              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <Text style={{ fontSize: 11, color: props.theme.textSecondary }}>加密口令</Text>
                <View style={{ flexDirection: 'row', gap: 8 }}>
                  <TouchableOpacity onPress={() => setShowSecret((s) => !s)}>
                    <Text style={{ fontSize: 12, fontWeight: '600', color: props.theme.textSecondary }}>
                      {showSecret ? '隐藏' : '显示'}
                    </Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    onPress={async () => {
                      await copyTextWithClipboard(item.password);
                      props.onToast('口令已复制（本地剪贴板 30s 保护）');
                    }}
                  >
                    <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                      复制口令
                    </Text>
                  </TouchableOpacity>
                </View>
              </View>

              <Text
                style={{
                  fontSize: 15,
                  fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                  fontWeight: '600',
                  color: props.theme.textPrimary,
                }}
                selectable
              >
                {showSecret ? item.password : '•'.repeat(Math.min(20, Math.max(10, item.password.length)))}
              </Text>

              <Text
                style={{
                  fontSize: 11,
                  fontWeight: '600',
                  color: entropy.score >= 3 ? props.theme.accent : props.theme.amber,
                }}
              >
                强度评估：{entropy.label} · {entropy.entropyBits} bits 熵
              </Text>
            </View>

            {totp && (
              <View
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  paddingTop: 10,
                  borderTopWidth: 1,
                  borderTopColor: props.theme.border,
                }}
              >
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
                  <IosTotpRing
                    progress={totp.progress}
                    remainingSeconds={totp.remainingSeconds}
                    theme={props.theme}
                  />
                  <View>
                    <Text style={{ fontSize: 11, color: props.theme.textSecondary }}>
                      动态两步验证码 (RFC 6238)
                    </Text>
                    <Text
                      style={{
                        fontSize: 19,
                        fontWeight: '800',
                        letterSpacing: 1.5,
                        fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                        color: props.theme.accent,
                      }}
                    >
                      {totp.formattedCode}
                    </Text>
                  </View>
                </View>

                <TouchableOpacity
                  onPress={async () => {
                    await copyTextWithClipboard(totp.code);
                    props.onToast(`2FA 动态码 ${totp.formattedCode} 已复制`);
                  }}
                  style={{
                    paddingHorizontal: 12,
                    paddingVertical: 7,
                    borderRadius: 999,
                    backgroundColor: props.theme.accentSoft,
                  }}
                >
                  <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                    复制 2FA
                  </Text>
                </TouchableOpacity>
              </View>
            )}

            {item.url ? (
              <View
                style={{
                  paddingTop: 8,
                  borderTopWidth: 1,
                  borderTopColor: props.theme.border,
                }}
              >
                <Text style={{ fontSize: 11, color: props.theme.textSecondary }}>
                  关联自动填充域名
                </Text>
                <Text
                  style={{ fontSize: 13, color: props.theme.accent, marginTop: 2 }}
                  selectable
                >
                  {item.url}
                </Text>
              </View>
            ) : null}
          </View>

          {item.customFields.length > 0 && (
            <View
              style={{
                backgroundColor: props.theme.bgCard,
                borderRadius: 15,
                padding: 14,
                gap: 10,
                borderWidth: 1,
                borderColor: props.theme.border,
              }}
            >
              <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.textSecondary }}>
                自定义加密隐藏字段
              </Text>
              {item.customFields.map((cf) => {
                const shown = !cf.hidden || Boolean(revealedIds[cf.id]);
                return (
                  <View
                    key={cf.id}
                    style={{
                      flexDirection: 'row',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <View style={{ flex: 1 }}>
                      <Text style={{ fontSize: 11, color: props.theme.textSecondary }}>
                        {cf.label}
                      </Text>
                      <Text
                        style={{
                          fontSize: 13,
                          fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                          color: props.theme.textPrimary,
                        }}
                      >
                        {shown ? cf.value : '••••••••••••'}
                      </Text>
                    </View>
                    <View style={{ flexDirection: 'row', gap: 8 }}>
                      {cf.hidden && (
                        <TouchableOpacity
                          onPress={() =>
                            setRevealedIds((p) => ({ ...p, [cf.id]: !p[cf.id] }))
                          }
                        >
                          <Text style={{ fontSize: 12, color: props.theme.textSecondary }}>
                            {shown ? '隐藏' : '查看'}
                          </Text>
                        </TouchableOpacity>
                      )}
                      <TouchableOpacity
                        onPress={async () => {
                          await copyTextWithClipboard(cf.value);
                          props.onToast(`已复制「${cf.label}」`);
                        }}
                      >
                        <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                          复制
                        </Text>
                      </TouchableOpacity>
                    </View>
                  </View>
                );
              })}
            </View>
          )}

          {item.notes ? (
            <View
              style={{
                backgroundColor: props.theme.bgCard,
                borderRadius: 15,
                padding: 14,
                borderWidth: 1,
                borderColor: props.theme.border,
              }}
            >
              <Text style={{ fontSize: 11, color: props.theme.textSecondary, marginBottom: 4 }}>
                加密备注
              </Text>
              <Text style={{ fontSize: 13, color: props.theme.textPrimary, lineHeight: 1.5 }}>
                {item.notes}
              </Text>
            </View>
          ) : null}

          {item.history.length > 0 && (
            <View
              style={{
                backgroundColor: props.theme.bgCard,
                borderRadius: 15,
                padding: 14,
                gap: 8,
                borderWidth: 1,
                borderColor: props.theme.border,
              }}
            >
              <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.textSecondary }}>
                历史口令版本 ({item.history.length})
              </Text>
              {item.history.map((h, idx) => (
                <View
                  key={`${h.changedAt}-${idx}`}
                  style={{
                    flexDirection: 'row',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <View>
                    <Text
                      style={{
                        fontSize: 12,
                        fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                        color: props.theme.textPrimary,
                      }}
                    >
                      {h.password}
                    </Text>
                    <Text style={{ fontSize: 10, color: props.theme.textTertiary }}>
                      {formatMobileShortTime(h.changedAt)}
                    </Text>
                  </View>
                  <TouchableOpacity
                    onPress={async () => {
                      await copyTextWithClipboard(h.password);
                      props.onToast('已复制历史口令');
                    }}
                  >
                    <Text style={{ fontSize: 12, color: props.theme.accent }}>复制</Text>
                  </TouchableOpacity>
                </View>
              ))}
            </View>
          )}

          {/* Actions */}
          <View
            style={{
              backgroundColor: props.theme.bgCard,
              borderRadius: 15,
              padding: 12,
              gap: 8,
              borderWidth: 1,
              borderColor: props.theme.border,
            }}
          >
            <TouchableOpacity
              onPress={() => void props.onUpdate(item.id, { isPinned: !item.isPinned })}
              style={{ paddingVertical: 8 }}
            >
              <Text style={{ fontSize: 13, fontWeight: '600', color: props.theme.textPrimary }}>
                {item.isPinned ? '取消置顶凭据' : '★ 置顶该凭据'}
              </Text>
            </TouchableOpacity>

            <TouchableOpacity
              onPress={() => {
                const id = item.id;
                props.onClose();
                props.onInspectCipher(id);
              }}
              style={{ paddingVertical: 8 }}
              testID="inspect-password-cipher-btn"
            >
              <Text style={{ fontSize: 13, fontWeight: '600', color: props.theme.accent }}>
                透视 SQLite AES-256-GCM 密文信封 (Rev #{item.revision})
              </Text>
            </TouchableOpacity>

            {item.isTrashed ? (
              <View style={{ flexDirection: 'row', gap: 12 }}>
                <TouchableOpacity
                  onPress={async () => {
                    await props.onUpdate(item.id, { isTrashed: false });
                    props.onClose();
                  }}
                  style={{ paddingVertical: 8 }}
                >
                  <Text style={{ fontSize: 13, fontWeight: '600', color: props.theme.accent }}>
                    从回收站恢复
                  </Text>
                </TouchableOpacity>
                <TouchableOpacity
                  onPress={async () => {
                    await props.onDeletePermanent(item.id);
                    props.onClose();
                  }}
                  style={{ paddingVertical: 8 }}
                >
                  <Text style={{ fontSize: 13, fontWeight: '700', color: props.theme.danger }}>
                    彻底销毁密文
                  </Text>
                </TouchableOpacity>
              </View>
            ) : (
              <TouchableOpacity
                onPress={async () => {
                  await props.onUpdate(item.id, { isTrashed: true });
                  props.onClose();
                }}
                style={{ paddingVertical: 8 }}
              >
                <Text style={{ fontSize: 13, fontWeight: '600', color: props.theme.danger }}>
                  移入回收站
                </Text>
              </TouchableOpacity>
            )}
          </View>
        </ScrollView>
      </View>
    </Modal>
  );
}

// ==================== 2. Create / Edit Password + Embedded Generator Modal ====================

export function IosPasswordEditorModal(props: {
  visible: boolean;
  existing: PasswordItem | null;
  client: PrivateSpaceMobileClient;
  theme: IosThemeTokens;
  onClose: () => void;
  onSave: (input: CreatePasswordRequest, existingId?: string, revision?: number) => Promise<void>;
}): React.JSX.Element | null {
  const [title, setTitle] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [category, setCategory] = useState<PasswordCategory>('login');
  const [notes, setNotes] = useState('');
  const [tagsText, setTagsText] = useState('');
  const [customFields, setCustomFields] = useState<PasswordCustomField[]>([]);

  useEffect(() => {
    if (!props.visible) return;
    if (props.existing) {
      setTitle(props.existing.title);
      setUsername(props.existing.username);
      setPassword(props.existing.password);
      setUrl(props.existing.url);
      setTotpSecret(props.existing.totpSecret);
      setCategory(props.existing.category);
      setNotes(props.existing.notes);
      setTagsText(props.existing.tags.join(', '));
      setCustomFields(props.existing.customFields);
    } else {
      setTitle('');
      setUsername('');
      setPassword(props.client.generateStrongPassword({ length: 22 }).password);
      setUrl('');
      setTotpSecret('');
      setCategory('login');
      setNotes('');
      setTagsText('');
      setCustomFields([]);
    }
  }, [props.visible, props.existing, props.client]);

  if (!props.visible) return null;
  const entropy = props.client.evaluateEntropy(password);

  const inputStyle = {
    backgroundColor: props.theme.bgInput,
    borderWidth: 1,
    borderColor: props.theme.border,
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 13,
    color: props.theme.textPrimary,
  };

  return (
    <Modal visible transparent animationType="slide" onRequestClose={props.onClose}>
      <View
        style={{
          maxHeight: '94%',
          backgroundColor: props.theme.bgPage,
          borderTopLeftRadius: 22,
          borderTopRightRadius: 22,
          overflow: 'hidden',
          borderTopWidth: 1,
          borderTopColor: props.theme.border,
        }}
      >
        <SheetHeader
          title={props.existing ? '编辑加密凭据' : '新建加密凭据'}
          leftLabel="取消"
          rightLabel="加密保存"
          onLeft={props.onClose}
          rightDisabled={!title.trim() && !url.trim()}
          onRight={() => {
            const tags = tagsText
              .split(',')
              .map((t) => t.trim())
              .filter(Boolean);
            void props
              .onSave(
                {
                  title: title.trim() || url.trim(),
                  username: username.trim(),
                  password,
                  url: url.trim(),
                  totpSecret: totpSecret.trim(),
                  category,
                  notes,
                  tags,
                  customFields: customFields.filter((f) => f.label.trim() || f.value.trim()),
                },
                props.existing?.id,
                props.existing?.revision,
              )
              .then(props.onClose);
          }}
          theme={props.theme}
        />

        <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
          <TextInput
            value={title}
            onChangeText={setTitle}
            placeholder="站点或凭据名称（例如 GitHub / AWS）"
            style={inputStyle}
            testID="pw-title-input"
          />
          <TextInput
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
            placeholder="账号 / 邮箱 / 手机号"
            style={inputStyle}
            testID="pw-username-input"
          />
          <TextInput
            value={url}
            onChangeText={setUrl}
            autoCapitalize="none"
            placeholder="关联网址（https://... 用于 iOS 自动填充匹配）"
            style={inputStyle}
          />

          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            <View style={{ flexDirection: 'row', gap: 6 }}>
              {PASSWORD_CATEGORIES.map((cat) => (
                <TouchableOpacity
                  key={cat.id}
                  onPress={() => setCategory(cat.id)}
                  style={{
                    paddingHorizontal: 11,
                    paddingVertical: 6,
                    borderRadius: 999,
                    backgroundColor:
                      category === cat.id ? props.theme.accent : props.theme.bgCard,
                    borderWidth: 1,
                    borderColor:
                      category === cat.id ? props.theme.accent : props.theme.border,
                  }}
                >
                  <Text
                    style={{
                      fontSize: 12,
                      fontWeight: '600',
                      color:
                        category === cat.id
                          ? props.theme.textOnAccent
                          : props.theme.textSecondary,
                    }}
                  >
                    {cat.label}
                  </Text>
                </TouchableOpacity>
              ))}
            </View>
          </ScrollView>

          <View
            style={{
              backgroundColor: props.theme.bgCard,
              padding: 12,
              borderRadius: 12,
              gap: 8,
              borderWidth: 1,
              borderColor: props.theme.border,
            }}
          >
            <View
              style={{
                flexDirection: 'row',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <Text style={{ fontSize: 11, fontWeight: '700', color: props.theme.textSecondary }}>
                口令 ({entropy.label} · {entropy.entropyBits} bits)
              </Text>
              <View style={{ flexDirection: 'row', gap: 8 }}>
                <TouchableOpacity
                  onPress={() =>
                    setPassword(props.client.generateStrongPassword({ length: 24 }).password)
                  }
                >
                  <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                    随机字符
                  </Text>
                </TouchableOpacity>
                <TouchableOpacity
                  onPress={() =>
                    setPassword(props.client.generatePassphrase({ wordCount: 4 }).password)
                  }
                >
                  <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                    助记词组
                  </Text>
                </TouchableOpacity>
              </View>
            </View>

            <TextInput
              value={password}
              onChangeText={setPassword}
              autoCapitalize="none"
              placeholder="输入或点击上方生成高熵口令"
              style={{
                ...inputStyle,
                fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
              }}
            />
          </View>

          <TextInput
            value={totpSecret}
            onChangeText={setTotpSecret}
            autoCapitalize="none"
            placeholder="2FA TOTP Base32 密钥或 otpauth://totp/..."
            style={{
              ...inputStyle,
              fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
            }}
          />

          <TextInput
            value={tagsText}
            onChangeText={setTagsText}
            placeholder="标签（逗号分隔，如 核心生产, 云平台）"
            style={inputStyle}
          />

          <TextInput
            value={notes}
            onChangeText={setNotes}
            multiline
            placeholder="加密备注说明..."
            style={{ ...inputStyle, minHeight: 72 }}
          />
        </ScrollView>
      </View>
    </Modal>
  );
}

// ==================== 3. Standalone CSPRNG Password Generator & CSV Import Modals ====================

export function IosPasswordGeneratorModal(props: {
  visible: boolean;
  client: PrivateSpaceMobileClient;
  theme: IosThemeTokens;
  onClose: () => void;
  onToast: (msg: string) => void;
}): React.JSX.Element | null {
  const [mode, setMode] = useState<'random' | 'passphrase'>('random');
  const [length, setLength] = useState(22);
  const [symbols, setSymbols] = useState(true);
  const [digits, setDigits] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(true);
  const [wordCount, setWordCount] = useState(4);
  const [generated, setGenerated] = useState(() =>
    props.client.generateStrongPassword({ length: 22 }).password,
  );

  useEffect(() => {
    if (!props.visible) return;
    if (mode === 'random') {
      setGenerated(
        props.client.generateStrongPassword({
          length,
          uppercase: true,
          lowercase: true,
          digits,
          symbols,
          excludeAmbiguous,
        }).password,
      );
    } else {
      setGenerated(
        props.client.generatePassphrase({
          wordCount,
          separator: '-',
          capitalize: true,
          includeNumber: true,
        }).password,
      );
    }
  }, [props.visible, mode, length, symbols, digits, excludeAmbiguous, wordCount, props.client]);

  if (!props.visible) return null;
  const entropy = props.client.evaluateEntropy(generated);

  return (
    <Modal visible transparent animationType="slide" onRequestClose={props.onClose}>
      <View
        style={{
          backgroundColor: props.theme.bgPage,
          borderTopLeftRadius: 22,
          borderTopRightRadius: 22,
          overflow: 'hidden',
          borderTopWidth: 1,
          borderTopColor: props.theme.border,
        }}
      >
        <SheetHeader
          title="CSPRNG 密码与助记词生成器"
          leftLabel="关闭"
          rightLabel="复制"
          onLeft={props.onClose}
          onRight={async () => {
            await copyTextWithClipboard(generated);
            props.onToast('高熵随机口令已复制');
          }}
          theme={props.theme}
        />

        <View style={{ padding: 16, gap: 14 }}>
          <View style={{ flexDirection: 'row', gap: 8 }}>
            {(
              [
                ['random', '无偏 CSPRNG 随机密码'],
                ['passphrase', '易记单词助记词组'],
              ] as const
            ).map(([id, label]) => (
              <TouchableOpacity
                key={id}
                onPress={() => setMode(id)}
                style={{
                  flex: 1,
                  alignItems: 'center',
                  paddingVertical: 8,
                  borderRadius: 10,
                  backgroundColor: mode === id ? props.theme.accent : props.theme.bgCard,
                }}
              >
                <Text
                  style={{
                    fontSize: 12,
                    fontWeight: '700',
                    color: mode === id ? props.theme.textOnAccent : props.theme.textSecondary,
                  }}
                >
                  {label}
                </Text>
              </TouchableOpacity>
            ))}
          </View>

          <View
            style={{
              backgroundColor: props.theme.bgCard,
              padding: 16,
              borderRadius: 14,
              gap: 6,
              borderWidth: 1,
              borderColor: props.theme.border,
            }}
          >
            <Text
              style={{
                fontSize: 16,
                fontWeight: '700',
                fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                color: props.theme.textPrimary,
              }}
              selectable
            >
              {generated}
            </Text>
            <Text style={{ fontSize: 11, color: props.theme.accent, fontWeight: '600' }}>
              强度：{entropy.label} · 约 {entropy.entropyBits} bits 熵
            </Text>
          </View>

          {mode === 'random' ? (
            <View
              style={{
                backgroundColor: props.theme.bgCard,
                padding: 14,
                borderRadius: 14,
                gap: 12,
                borderWidth: 1,
                borderColor: props.theme.border,
              }}
            >
              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <Text style={{ fontSize: 13, color: props.theme.textPrimary }}>
                  口令长度：{length} 位
                </Text>
                <View style={{ flexDirection: 'row', gap: 8 }}>
                  {[16, 22, 32].map((len) => (
                    <TouchableOpacity
                      key={len}
                      onPress={() => setLength(len)}
                      style={{
                        paddingHorizontal: 10,
                        paddingVertical: 4,
                        borderRadius: 8,
                        backgroundColor:
                          length === len ? props.theme.accentSoft : props.theme.bgSubtle,
                      }}
                    >
                      <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                        {len}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>

              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <Text style={{ fontSize: 13, color: props.theme.textPrimary }}>包含特殊符号</Text>
                <Switch value={symbols} onValueChange={setSymbols} />
              </View>

              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <Text style={{ fontSize: 13, color: props.theme.textPrimary }}>包含数字</Text>
                <Switch value={digits} onValueChange={setDigits} />
              </View>

              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <Text style={{ fontSize: 13, color: props.theme.textPrimary }}>
                  排除易混淆字符 (0/O/1/l/I)
                </Text>
                <Switch value={excludeAmbiguous} onValueChange={setExcludeAmbiguous} />
              </View>
            </View>
          ) : (
            <View
              style={{
                backgroundColor: props.theme.bgCard,
                padding: 14,
                borderRadius: 14,
                flexDirection: 'row',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderWidth: 1,
                borderColor: props.theme.border,
              }}
            >
              <Text style={{ fontSize: 13, color: props.theme.textPrimary }}>
                词组长度：{wordCount} 个单词
              </Text>
              <View style={{ flexDirection: 'row', gap: 8 }}>
                {[4, 5, 6].map((cnt) => (
                  <TouchableOpacity
                    key={cnt}
                    onPress={() => setWordCount(cnt)}
                    style={{
                      paddingHorizontal: 10,
                      paddingVertical: 4,
                      borderRadius: 8,
                      backgroundColor:
                        wordCount === cnt ? props.theme.accentSoft : props.theme.bgSubtle,
                    }}
                  >
                    <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                      {cnt} 词
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>
            </View>
          )}
        </View>
      </View>
    </Modal>
  );
}

export function IosCsvImportModal(props: {
  visible: boolean;
  theme: IosThemeTokens;
  onClose: () => void;
  onImport: (csvText: string) => Promise<void>;
}): React.JSX.Element | null {
  const [csv, setCsv] = useState('');
  if (!props.visible) return null;
  const parsedCount = parseMobilePasswordCsv(csv).length;

  return (
    <Modal visible transparent animationType="slide" onRequestClose={props.onClose}>
      <View
        style={{
          backgroundColor: props.theme.bgPage,
          borderTopLeftRadius: 22,
          borderTopRightRadius: 22,
          overflow: 'hidden',
          borderTopWidth: 1,
          borderTopColor: props.theme.border,
        }}
      >
        <SheetHeader
          title="CSV 密码批量加密导入"
          leftLabel="取消"
          rightLabel={`导入 (${parsedCount})`}
          rightDisabled={parsedCount === 0}
          onLeft={props.onClose}
          onRight={() => void props.onImport(csv).then(props.onClose)}
          theme={props.theme}
        />
        <View style={{ padding: 16, gap: 10 }}>
          <Text style={{ fontSize: 12, color: props.theme.textSecondary }}>
            兼容 Apple 密码、Chrome、1Password、Bitwarden 导出的 CSV 格式：
          </Text>
          <TextInput
            value={csv}
            onChangeText={setCsv}
            multiline
            placeholder={'name,url,username,password,totp\nGitHub,https://github.com,me@io.dev,Secret!99,JBSWY3DPEHPK3PXP'}
            style={{
              minHeight: 140,
              backgroundColor: props.theme.bgInput,
              borderWidth: 1,
              borderColor: props.theme.border,
              borderRadius: 12,
              padding: 12,
              fontSize: 12,
              fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
              color: props.theme.textPrimary,
            }}
          />
        </View>
      </View>
    </Modal>
  );
}

// ==================== 4. Darkroom Photo Lightbox & HTTP 206 Video Cinema ====================

export function IosDarkroomPhotoModal(props: {
  media: MediaItem | null;
  client: PrivateSpaceMobileClient;
  theme: IosThemeTokens;
  onClose: () => void;
  onUpdate: (id: string, patch: UpdateMediaRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onInspectCipher: (id: string) => void;
}): React.JSX.Element | null {
  const [zoom, setZoom] = useState(1);
  const [deg, setDeg] = useState(0);
  const [flip, setFlip] = useState(false);

  if (!props.media) return null;
  const media = props.media;

  return (
    <Modal visible transparent animationType="fade" onRequestClose={props.onClose}>
      <View
        style={{
          flex: 1,
          backgroundColor: '#0A0D0E',
          justifyContent: 'space-between',
        }}
      >
        <View
          style={{
            flexDirection: 'row',
            justifyContent: 'space-between',
            alignItems: 'center',
            paddingHorizontal: 16,
            paddingVertical: 14,
            backgroundColor: 'rgba(0,0,0,0.52)',
          }}
        >
          <TouchableOpacity onPress={props.onClose} testID="close-lightbox-btn">
            <Text style={{ fontSize: 14, fontWeight: '700', color: '#FFFFFF' }}>✕ 关闭</Text>
          </TouchableOpacity>
          <View style={{ alignItems: 'center' }}>
            <Text style={{ fontSize: 13, fontWeight: '700', color: '#FFFFFF' }} numberOfLines={1}>
              {media.title}
            </Text>
            <Text style={{ fontSize: 10, color: 'rgba(255,255,255,0.68)' }}>
              {media.width}×{media.height} · {formatMobileBytes(media.byteSize)} · PSENC001 (
              {media.chunkCount} 块)
            </Text>
          </View>
          <TouchableOpacity
            onPress={() => {
              const id = media.id;
              props.onClose();
              props.onInspectCipher(id);
            }}
          >
            <Text style={{ fontSize: 12, fontWeight: '700', color: '#4CB997' }}>密文透视</Text>
          </TouchableOpacity>
        </View>

        <View
          style={{
            flex: 1,
            alignItems: 'center',
            justifyContent: 'center',
            overflow: 'hidden',
            padding: 12,
          }}
        >
          <Image
            source={{ uri: props.client.getStreamUrl(media.id, media.revision) }}
            resizeMode="contain"
            style={{
              width: '100%',
              height: 360,
              transform: [
                { scale: zoom },
                { rotate: `${deg}deg` },
                { scaleX: flip ? -1 : 1 },
              ],
            }}
          />
        </View>

        <View
          style={{
            flexDirection: 'row',
            justifyContent: 'space-around',
            alignItems: 'center',
            paddingVertical: 14,
            paddingHorizontal: 12,
            backgroundColor: 'rgba(18, 22, 24, 0.92)',
            borderTopWidth: 1,
            borderTopColor: 'rgba(255,255,255,0.12)',
          }}
        >
          <TouchableOpacity onPress={() => setZoom((z) => (z >= 2.2 ? 1 : Number((z + 0.6).toFixed(1))))}>
            <Text style={{ fontSize: 12, fontWeight: '600', color: '#FFFFFF' }}>
              缩放 {zoom}×
            </Text>
          </TouchableOpacity>
          <TouchableOpacity onPress={() => setDeg((d) => (d + 90) % 360)}>
            <Text style={{ fontSize: 12, fontWeight: '600', color: '#FFFFFF' }}>旋转 90°</Text>
          </TouchableOpacity>
          <TouchableOpacity onPress={() => setFlip((f) => !f)}>
            <Text style={{ fontSize: 12, fontWeight: '600', color: '#FFFFFF' }}>镜像翻转</Text>
          </TouchableOpacity>
          <TouchableOpacity
            onPress={() => void props.onUpdate(media.id, { isPinned: !media.isPinned })}
          >
            <Text style={{ fontSize: 12, fontWeight: '600', color: '#F5C451' }}>
              {media.isPinned ? '★ 已星标' : '☆ 星标'}
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            onPress={async () => {
              if (media.isTrashed) {
                await props.onDeletePermanent(media.id);
              } else {
                await props.onUpdate(media.id, { isTrashed: true });
              }
              props.onClose();
            }}
          >
            <Text style={{ fontSize: 12, fontWeight: '700', color: '#E05A52' }}>
              {media.isTrashed ? '彻底擦除' : '删除'}
            </Text>
          </TouchableOpacity>
        </View>
      </View>
    </Modal>
  );
}

export function IosVideoCinemaModal(props: {
  video: MediaItem | null;
  client: PrivateSpaceMobileClient;
  theme: IosThemeTokens;
  onClose: () => void;
  onUpdate: (id: string, patch: UpdateMediaRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onInspectCipher: (id: string) => void;
}): React.JSX.Element | null {
  if (!props.video) return null;
  const video = props.video;

  return (
    <Modal visible transparent animationType="slide" onRequestClose={props.onClose}>
      <View
        style={{
          maxHeight: '92%',
          backgroundColor: props.theme.bgPage,
          borderTopLeftRadius: 22,
          borderTopRightRadius: 22,
          overflow: 'hidden',
          borderTopWidth: 1,
          borderTopColor: props.theme.border,
        }}
      >
        <SheetHeader
          title={video.title}
          leftLabel="完成"
          rightLabel="PSENC001"
          onLeft={props.onClose}
          onRight={() => {
            const id = video.id;
            props.onClose();
            props.onInspectCipher(id);
          }}
          theme={props.theme}
        />

        <ScrollView contentContainerStyle={{ padding: 16, gap: 14 }}>
          <IosStreamingVideoSurface
            streamUrl={props.client.getStreamUrl(video.id, video.revision)}
            posterUrl={
              video.hasThumbnail
                ? props.client.getThumbnailUrl(video.id, video.revision)
                : undefined
            }
            theme={props.theme}
          />

          <View
            style={{
              backgroundColor: props.theme.bgCard,
              borderRadius: 14,
              padding: 14,
              gap: 6,
              borderWidth: 1,
              borderColor: props.theme.border,
            }}
          >
            <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.textPrimary }}>
              HTTP 206 随机分块实时解密流信息
            </Text>
            <Text style={{ fontSize: 12, color: props.theme.textSecondary }}>
              规格：{video.width > 0 ? `${video.width}×${video.height} · ` : ''}
              {formatMobileDuration(video.durationMs)} · 明文 {formatMobileBytes(video.byteSize)}
            </Text>
            <Text style={{ fontSize: 12, color: props.theme.textSecondary }}>
              磁盘密文：{formatMobileBytes(video.encryptedSize)} ({video.chunkCount} 个 64KiB
              AES-256-GCM 密文块)
            </Text>
            <Text
              style={{
                fontSize: 11,
                fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                color: props.theme.textTertiary,
              }}
            >
              SHA-256: {video.sha256.slice(0, 28)}…
            </Text>
          </View>
        </ScrollView>
      </View>
    </Modal>
  );
}

// ==================== 5. Markdown & Interactive Checklist Note Editor Modal ====================

export function IosNoteEditorModal(props: {
  note: NoteItem | null;
  theme: IosThemeTokens;
  onClose: () => void;
  onSave: (id: string, patch: UpdateNoteRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onInspectCipher: (id: string) => void;
}): React.JSX.Element | null {
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [tagsText, setTagsText] = useState('');
  const [preview, setPreview] = useState(false);

  useEffect(() => {
    if (!props.note) return;
    setTitle(props.note.title);
    setContent(props.note.content);
    setTagsText(props.note.tags.join(', '));
    setPreview(false);
  }, [props.note]);

  if (!props.note) return null;
  const note = props.note;

  const persistNow = async (nextContent = content) => {
    const tags = tagsText
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
    await props.onSave(note.id, {
      title,
      content: nextContent,
      tags,
    });
  };

  const toggleTodoLine = (lineIdx: number) => {
    const lines = content.split('\n');
    const cur = lines[lineIdx] ?? '';
    if (cur.includes('- [ ] ')) {
      lines[lineIdx] = cur.replace('- [ ] ', '- [x] ');
    } else {
      lines[lineIdx] = cur.replace(/- \[[xX]\] /, '- [ ] ');
    }
    const updated = lines.join('\n');
    setContent(updated);
    void persistNow(updated);
  };

  return (
    <Modal visible transparent animationType="slide" onRequestClose={props.onClose}>
      <View
        style={{
          height: '93%',
          backgroundColor: props.theme.bgPage,
          borderTopLeftRadius: 22,
          borderTopRightRadius: 22,
          overflow: 'hidden',
          borderTopWidth: 1,
          borderTopColor: props.theme.border,
        }}
      >
        <SheetHeader
          title={title.trim() || '加密文本笔记'}
          leftLabel="返回"
          rightLabel="保存"
          onLeft={() => {
            void persistNow().then(props.onClose);
          }}
          onRight={() => void persistNow().then(props.onClose)}
          theme={props.theme}
        />

        <View style={{ paddingHorizontal: 16, paddingTop: 10, gap: 8 }}>
          <View style={{ flexDirection: 'row', gap: 8 }}>
            <TouchableOpacity
              onPress={() => setPreview(false)}
              style={{
                flex: 1,
                alignItems: 'center',
                paddingVertical: 6,
                borderRadius: 8,
                backgroundColor: !preview ? props.theme.accent : props.theme.bgSubtle,
              }}
            >
              <Text
                style={{
                  fontSize: 12,
                  fontWeight: '700',
                  color: !preview ? props.theme.textOnAccent : props.theme.textSecondary,
                }}
              >
                Markdown 编辑
              </Text>
            </TouchableOpacity>
            <TouchableOpacity
              onPress={() => setPreview(true)}
              style={{
                flex: 1,
                alignItems: 'center',
                paddingVertical: 6,
                borderRadius: 8,
                backgroundColor: preview ? props.theme.accent : props.theme.bgSubtle,
              }}
            >
              <Text
                style={{
                  fontSize: 12,
                  fontWeight: '700',
                  color: preview ? props.theme.textOnAccent : props.theme.textSecondary,
                }}
              >
                交互预览
              </Text>
            </TouchableOpacity>
          </View>
        </View>

        <ScrollView style={{ flex: 1 }} contentContainerStyle={{ padding: 16, gap: 10 }}>
          {!preview ? (
            <>
              <TextInput
                value={title}
                onChangeText={setTitle}
                placeholder="输入笔记标题..."
                style={{
                  fontSize: 18,
                  fontWeight: '700',
                  color: props.theme.textPrimary,
                  paddingVertical: 6,
                  backgroundColor: 'transparent',
                  borderWidth: 0,
                }}
                testID="ios-note-title-input"
              />
              <TextInput
                value={tagsText}
                onChangeText={setTagsText}
                placeholder="标签（逗号分隔，如 备忘, 私密清单）"
                style={{
                  fontSize: 12,
                  color: props.theme.accent,
                  backgroundColor: props.theme.bgInput,
                  paddingHorizontal: 10,
                  paddingVertical: 7,
                  borderRadius: 8,
                  borderWidth: 1,
                  borderColor: props.theme.border,
                }}
              />

              <View style={{ flexDirection: 'row', gap: 6 }}>
                {[
                  ['+ 待办', '\n- [ ] 待办事项'],
                  ['**粗体**', '**重点**'],
                  ['`代码`', ' `code` '],
                  ['## 标题', '\n## 小节标题\n'],
                ].map(([lbl, snippet]) => (
                  <TouchableOpacity
                    key={lbl}
                    onPress={() => setContent((c) => `${c}${snippet}`)}
                    style={{
                      paddingHorizontal: 9,
                      paddingVertical: 5,
                      borderRadius: 7,
                      backgroundColor: props.theme.bgSubtle,
                    }}
                  >
                    <Text style={{ fontSize: 11, fontWeight: '600', color: props.theme.textPrimary }}>
                      {lbl}
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>

              <TextInput
                value={content}
                onChangeText={setContent}
                multiline
                placeholder="在此撰写 Markdown 文本笔记（保存时自动经 HKDF-SHA256 + AES-256-GCM 独立子密钥加密）..."
                style={{
                  minHeight: 240,
                  fontSize: 14,
                  lineHeight: 1.6,
                  color: props.theme.textPrimary,
                  backgroundColor: props.theme.bgCard,
                  borderRadius: 12,
                  padding: 12,
                  borderWidth: 1,
                  borderColor: props.theme.border,
                }}
                testID="ios-note-body-input"
              />
            </>
          ) : (
            <View
              style={{
                backgroundColor: props.theme.bgCard,
                borderRadius: 14,
                padding: 16,
                gap: 8,
                borderWidth: 1,
                borderColor: props.theme.border,
              }}
            >
              <Text style={{ fontSize: 19, fontWeight: '800', color: props.theme.textPrimary }}>
                {title || '无标题加密笔记'}
              </Text>
              {content.split('\n').map((line, idx) => {
                const trimmed = line.trim();
                if (/^- \[[ xX]\] /.test(trimmed)) {
                  const checked = !trimmed.startsWith('- [ ] ');
                  const textBody = trimmed.slice(6);
                  return (
                    <TouchableOpacity
                      key={idx}
                      onPress={() => toggleTodoLine(idx)}
                      style={{ flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 2 }}
                    >
                      <Text style={{ fontSize: 15, color: props.theme.accent }}>
                        {checked ? '☑' : '☐'}
                      </Text>
                      <Text
                        style={{
                          fontSize: 14,
                          color: checked ? props.theme.textTertiary : props.theme.textPrimary,
                          textDecorationLine: checked ? 'line-through' : 'none',
                        }}
                      >
                        {textBody}
                      </Text>
                    </TouchableOpacity>
                  );
                }
                if (trimmed.startsWith('## ')) {
                  return (
                    <Text
                      key={idx}
                      style={{
                        fontSize: 15,
                        fontWeight: '700',
                        color: props.theme.textPrimary,
                        marginTop: 6,
                      }}
                    >
                      {trimmed.slice(3)}
                    </Text>
                  );
                }
                return (
                  <Text
                    key={idx}
                    style={{ fontSize: 14, lineHeight: 1.55, color: props.theme.textPrimary }}
                  >
                    {line || ' '}
                  </Text>
                );
              })}
            </View>
          )}

          <View
            style={{
              flexDirection: 'row',
              justifyContent: 'space-between',
              alignItems: 'center',
              paddingTop: 6,
            }}
          >
            <TouchableOpacity
              onPress={() => {
                const id = note.id;
                props.onClose();
                props.onInspectCipher(id);
              }}
            >
              <Text style={{ fontSize: 12, fontWeight: '600', color: props.theme.accent }}>
                密文透视 (Rev #{note.revision})
              </Text>
            </TouchableOpacity>

            <View style={{ flexDirection: 'row', gap: 14 }}>
              <TouchableOpacity
                onPress={() => void props.onSave(note.id, { isPinned: !note.isPinned })}
              >
                <Text style={{ fontSize: 12, fontWeight: '600', color: props.theme.amber }}>
                  {note.isPinned ? '取消置顶' : '置顶'}
                </Text>
              </TouchableOpacity>
              <TouchableOpacity
                onPress={async () => {
                  if (note.isTrashed) {
                    await props.onDeletePermanent(note.id);
                  } else {
                    await props.onSave(note.id, { isTrashed: true });
                  }
                  props.onClose();
                }}
              >
                <Text style={{ fontSize: 12, fontWeight: '600', color: props.theme.danger }}>
                  {note.isTrashed ? '彻底销毁' : '移入回收站'}
                </Text>
              </TouchableOpacity>
            </View>
          </View>
        </ScrollView>
      </View>
    </Modal>
  );
}

// ==================== 6. Universal Cipher Envelope Inspector Modal ====================

export function IosCipherInspectorModal(props: {
  itemId: string | null;
  client: PrivateSpaceMobileClient;
  theme: IosThemeTokens;
  onClose: () => void;
}): React.JSX.Element | null {
  const [env, setEnv] = useState<CipherEnvelopeInspection | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!props.itemId) {
      setEnv(null);
      setErr(null);
      return;
    }
    setEnv(null);
    setErr(null);
    props.client
      .inspectCipher(props.itemId)
      .then(setEnv)
      .catch((e) => setErr(e instanceof Error ? e.message : '读取密文信封失败'));
  }, [props.itemId, props.client]);

  if (!props.itemId) return null;

  return (
    <Modal visible transparent animationType="slide" onRequestClose={props.onClose}>
      <View
        style={{
          maxHeight: '90%',
          backgroundColor: props.theme.bgPage,
          borderTopLeftRadius: 22,
          borderTopRightRadius: 22,
          overflow: 'hidden',
          borderTopWidth: 1,
          borderTopColor: props.theme.border,
        }}
      >
        <SheetHeader
          title="SQLite / PSENC001 密文信封透视"
          leftLabel="关闭"
          onLeft={props.onClose}
          theme={props.theme}
        />

        <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
          {err ? (
            <Text style={{ fontSize: 13, color: props.theme.danger }}>{err}</Text>
          ) : !env ? (
            <Text style={{ fontSize: 13, color: props.theme.textSecondary }}>
              正在读取服务端底层加密信封...
            </Text>
          ) : (
            <>
              <View
                style={{
                  backgroundColor: props.theme.bgCard,
                  borderRadius: 14,
                  padding: 14,
                  gap: 6,
                  borderWidth: 1,
                  borderColor: props.theme.border,
                }}
              >
                <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                  {env.algorithm} · {env.itemType.toUpperCase()} · Rev #{env.revision} · Seq #
                  {env.syncSeq}
                </Text>
                <Text
                  style={{
                    fontSize: 11,
                    fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                    color: props.theme.textSecondary,
                  }}
                  selectable
                >
                  HKDF: {env.hkdfContext}
                </Text>
                <Text
                  style={{
                    fontSize: 11,
                    fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                    color: props.theme.textSecondary,
                  }}
                  selectable
                >
                  AAD: {env.aadJson}
                </Text>
              </View>

              <View
                style={{
                  backgroundColor: props.theme.bgCard,
                  borderRadius: 14,
                  padding: 14,
                  gap: 8,
                  borderWidth: 1,
                  borderColor: props.theme.border,
                }}
              >
                {[
                  ['128-bit Item Salt (Hex)', env.saltHex],
                  ['96-bit GCM Nonce (Hex)', env.nonceHex],
                  ['128-bit Auth Tag (Hex)', env.authTagHex],
                  [`密文载荷采样 (${env.ciphertextTotalBytes} B)`, env.ciphertextPreviewHex],
                ].map(([label, hex]) => (
                  <View key={label} style={{ gap: 2 }}>
                    <Text style={{ fontSize: 11, color: props.theme.textSecondary }}>{label}</Text>
                    <Text
                      style={{
                        fontSize: 11,
                        fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                        color: props.theme.textPrimary,
                      }}
                      selectable
                    >
                      {hex}
                    </Text>
                  </View>
                ))}
              </View>

              {env.chunkStore && (
                <View
                  style={{
                    backgroundColor: props.theme.bgCard,
                    borderRadius: 14,
                    padding: 14,
                    gap: 6,
                    borderWidth: 1,
                    borderColor: props.theme.border,
                  }}
                >
                  <Text style={{ fontSize: 12, fontWeight: '700', color: props.theme.accent }}>
                    {env.chunkStore.formatMagic} 分块认证加密容器 (.psenc)
                  </Text>
                  <Text style={{ fontSize: 12, color: props.theme.textSecondary }}>
                    分块数：{env.chunkStore.chunkCount} 块 ×{' '}
                    {formatMobileBytes(env.chunkStore.chunkPlainBytes)} · 磁盘密文{' '}
                    {formatMobileBytes(env.chunkStore.encryptedDiskBytes)}
                  </Text>
                  <Text
                    style={{
                      fontSize: 11,
                      fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                      color: props.theme.textTertiary,
                    }}
                    selectable
                  >
                    SHA-256: {env.chunkStore.sha256Hex}
                  </Text>
                </View>
              )}
            </>
          )}
        </ScrollView>
      </View>
    </Modal>
  );
}
