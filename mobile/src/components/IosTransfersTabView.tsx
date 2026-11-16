import React, { useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator,
  Image,
  ScrollView,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import type {
  CreateTransferTextRequest,
  MediaKind,
  TransferDevicePlatform,
  TransferItem,
  UpdateTransferRequest,
} from '@shared/types';
import { copyTextWithClipboard, pickLocalMediaFiles } from '../iosNativeBridge';
import { formatMobileBytes, type IosThemeTokens } from '../iosTheme';
import type { PrivateSpaceMobileClient } from '../syncClient';

export interface IosTransfersTabViewProps {
  client: PrivateSpaceMobileClient;
  transfers: TransferItem[];
  theme: IosThemeTokens;
  onSendText: (input: CreateTransferTextRequest) => Promise<void>;
  onSendPickedFiles: (
    files: Array<{ name: string; type: string; bytes: Uint8Array }>,
    opts?: { text?: string; replyToId?: string | null; replyPreview?: string | null },
  ) => Promise<void>;
  onUpdateTransfer: (id: string, patch: UpdateTransferRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onJumpToMediaTab: (kind: MediaKind, linkedMediaId?: string | null) => void;
  onInspectCipher: (id: string) => void;
  onToast: (msg: string) => void;
}

type IosTransferFilter = 'all' | 'text' | 'file' | 'media' | 'pinned';

function platformBadgeText(platform: TransferDevicePlatform): string {
  switch (platform) {
    case 'ios':
      return 'iOS';
    case 'android':
      return 'Android';
    case 'web':
      return '电脑端';
    case 'api':
      return 'API';
  }
}

function extBadge(filename: string): string {
  const idx = filename.lastIndexOf('.');
  if (idx <= 0 || idx === filename.length - 1) return 'FILE';
  return filename.slice(idx + 1).toUpperCase().slice(0, 5);
}

function formatIosTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const now = new Date();
  const hm = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  if (
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  ) {
    return `今天 ${hm}`;
  }
  return `${d.getMonth() + 1}/${d.getDate()} ${hm}`;
}

function summarizeReply(item: TransferItem): string {
  const sender = item.senderDeviceName || platformBadgeText(item.senderPlatform);
  if (item.messageKind === 'text') {
    return `${sender}: ${item.text.replace(/\s+/g, ' ').trim().slice(0, 72)}`;
  }
  return `${sender}: [${item.messageKind === 'image' ? '图片' : item.messageKind === 'video' ? '视频' : '文件'}] ${item.originalFilename}`;
}

function IosTransferThumb(props: {
  item: TransferItem;
  client: PrivateSpaceMobileClient;
  theme: IosThemeTokens;
}): React.JSX.Element {
  const [uri, setUri] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setUri(null);
    const loader = props.item.hasThumbnail
      ? props.client.loadTransferThumbnailObjectUrl(props.item)
      : props.item.messageKind === 'image'
        ? props.client.loadTransferObjectUrl(props.item)
        : Promise.resolve<string | null>(null);

    loader
      .then((u) => {
        if (!cancelled && u) setUri(u);
      })
      .catch(() => {
        if (!cancelled) setUri(null);
      });
    return () => {
      cancelled = true;
    };
  }, [props.client, props.item]);

  if (!uri) {
    return (
      <View
        style={{
          width: '100%',
          height: 156,
          borderRadius: 12,
          backgroundColor: '#121918',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 4,
        }}
      >
        <Text style={{ fontSize: 12, fontWeight: '700', color: '#DCE5E2' }}>
          {props.item.messageKind === 'video' ? '▶ 加密视频流' : '▣ 加密原图'}
        </Text>
        <Text style={{ fontSize: 11, color: '#94A39E' }} numberOfLines={1}>
          {props.item.originalFilename}
        </Text>
      </View>
    );
  }

  return (
    <View
      style={{
        width: '100%',
        height: 168,
        borderRadius: 12,
        overflow: 'hidden',
        backgroundColor: '#121918',
        position: 'relative',
      }}
    >
      <Image source={{ uri }} resizeMode="cover" style={{ width: '100%', height: '100%' }} />
      {props.item.messageKind === 'video' && (
        <View
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            marginLeft: -20,
            marginTop: -20,
            width: 40,
            height: 40,
            borderRadius: 20,
            backgroundColor: 'rgba(16, 22, 21, 0.75)',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Text style={{ color: '#FFFFFF', fontSize: 15, fontWeight: '800' }}>▶</Text>
        </View>
      )}
      <View
        style={{
          position: 'absolute',
          right: 8,
          bottom: 7,
          paddingHorizontal: 7,
          paddingVertical: 2,
          borderRadius: 6,
          backgroundColor: 'rgba(12, 18, 17, 0.72)',
        }}
      >
        <Text style={{ fontSize: 10, fontWeight: '700', color: '#F3F7F5' }}>
          {formatMobileBytes(props.item.plainSize)}
        </Text>
      </View>
    </View>
  );
}

export function IosTransfersTabView(props: IosTransfersTabViewProps): React.JSX.Element {
  const { client, transfers, theme } = props;
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<IosTransferFilter>('all');
  const [draft, setDraft] = useState('');
  const [sending, setSending] = useState(false);
  const [replyTarget, setReplyTarget] = useState<TransferItem | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const sessionId = client.getSessionId();
  const deviceName = client.getDeviceName();
  const platform = client.getPlatform();

  // Newest-first or chronological? Let's display composer + search at top and chronological messages newest-at-bottom or clean feed;
  // inside iOS ScrollView, showing Composer Card at top + newest-first OR chronological timeline:
  // Let's show Composer + Search at top, and messages sorted newest-first OR chronological with clear timestamps.
  // Actually, chronological (oldest -> newest) or newest-first? In a ScrollView page, newest-first makes the latest message sent from Desktop immediately visible at the top without scrolling, OR chronological when <= 12 items! Wait: let's check — in `TransferHubView` and `MobileTransferTab` we used chronological chat order; in `IosTransfersTabView` (which sits inside `App.tsx`'s outer `ScrollView`), newest-first OR a compact composer at the bottom of the card list? Putting Composer + Search at top and newest-first (with a toggle or clear badge) OR chronological? Let's put Search + Filter + Quick Send Composer at the top so the user can immediately type/pick files AND see the latest synced transfers right below! Let's sort newest-first (`b.createdAt.localeCompare(a.createdAt)`) or chronological? Let's provide chronological order inside a dedicated chat stream card so conversation replies read naturally top-to-bottom!
  const chronological = useMemo(() => {
    return [...transfers].sort((a, b) => {
      const cmp = a.createdAt.localeCompare(b.createdAt);
      if (cmp !== 0) return cmp;
      return a.syncSeq - b.syncSeq;
    });
  }, [transfers]);

  const counts = useMemo(() => {
    let text = 0;
    let file = 0;
    let media = 0;
    let pinned = 0;
    for (const item of chronological) {
      if (item.messageKind === 'text') text += 1;
      else if (item.messageKind === 'file') file += 1;
      else media += 1;
      if (item.isPinned) pinned += 1;
    }
    return { all: chronological.length, text, file, media, pinned };
  }, [chronological]);

  const visibleItems = useMemo(() => {
    const q = query.trim().toLowerCase();
    return chronological.filter((item) => {
      if (filter === 'text' && item.messageKind !== 'text') return false;
      if (filter === 'file' && item.messageKind !== 'file') return false;
      if (filter === 'media' && item.messageKind !== 'image' && item.messageKind !== 'video') {
        return false;
      }
      if (filter === 'pinned' && !item.isPinned) return false;
      if (!q) return true;
      return (
        item.text.toLowerCase().includes(q) ||
        item.originalFilename.toLowerCase().includes(q) ||
        item.mimeType.toLowerCase().includes(q) ||
        item.senderDeviceName.toLowerCase().includes(q) ||
        item.senderPlatform.toLowerCase().includes(q) ||
        item.sha256.toLowerCase().includes(q) ||
        item.tags.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [chronological, filter, query]);

  const isSelfItem = (item: TransferItem): boolean => {
    if (sessionId && item.senderSessionId) return item.senderSessionId === sessionId;
    return item.senderPlatform === platform && item.senderDeviceName === deviceName;
  };

  const handleSendTextNow = async () => {
    const trimmed = draft.trim();
    if (!trimmed || sending) return;
    setSending(true);
    try {
      await props.onSendText({
        text: trimmed,
        replyToId: replyTarget?.id ?? null,
        replyPreview: replyTarget ? summarizeReply(replyTarget) : null,
      });
      setDraft('');
      setReplyTarget(null);
    } catch (err) {
      props.onToast(err instanceof Error ? err.message : '发送加密消息失败');
    } finally {
      setSending(false);
    }
  };

  const handlePickAndSend = async (accept: string) => {
    const files = await pickLocalMediaFiles(accept, true);
    if (!files.length) return;
    const caption = draft.trim();
    const reply = replyTarget;
    setDraft('');
    setReplyTarget(null);
    await props.onSendPickedFiles(files, {
      text: caption || undefined,
      replyToId: reply?.id ?? null,
      replyPreview: reply ? summarizeReply(reply) : null,
    });
  };

  const handleDownload = async (item: TransferItem) => {
    setDownloadingId(item.id);
    try {
      await client.downloadDecryptedTransfer(item);
      props.onToast(`已解密导出：${item.originalFilename || '互传文件'}`);
    } catch (err) {
      props.onToast(err instanceof Error ? err.message : '解密导出失败');
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <View style={{ gap: 12 }} testID="ios-transfers-tab-view">
      {/* Banner & Search + Filter Card */}
      <View
        style={{
          backgroundColor: theme.bgCard,
          borderRadius: 16,
          padding: 14,
          gap: 10,
          borderWidth: 1,
          borderColor: theme.border,
        }}
      >
        <View
          style={{
            flexDirection: 'row',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <View style={{ gap: 2 }}>
            <Text style={{ fontSize: 15, fontWeight: '800', color: theme.textPrimary }}>
              多端加密互传
            </Text>
            <Text style={{ fontSize: 11, color: theme.textSecondary }}>
              电脑与手机互发文件与聊天 · 记录永久保存 · 图影自动入库
            </Text>
          </View>
          <View
            style={{
              backgroundColor: theme.accentSoft,
              borderRadius: 999,
              paddingHorizontal: 9,
              paddingVertical: 4,
              borderWidth: 1,
              borderColor: theme.accentBorder,
            }}
          >
            <Text style={{ fontSize: 11, fontWeight: '800', color: theme.accent }}>
              {counts.all} 条永久记录
            </Text>
          </View>
        </View>

        <TextInput
          value={query}
          onChangeText={setQuery}
          placeholder="搜索消息文本、文件名、扩展名或发送设备..."
          style={{
            backgroundColor: theme.bgInput,
            borderWidth: 1,
            borderColor: theme.border,
            borderRadius: 11,
            paddingHorizontal: 12,
            paddingVertical: 9,
            fontSize: 13,
            color: theme.textPrimary,
          }}
          testID="ios-transfer-search"
        />

        <ScrollView horizontal showsHorizontalScrollIndicator={false}>
          <View style={{ flexDirection: 'row', gap: 7 }}>
            {(
              [
                ['all', `全部 (${counts.all})`],
                ['text', `文本 (${counts.text})`],
                ['file', `文件 (${counts.file})`],
                ['media', `图影 (${counts.media})`],
                ['pinned', `收藏 (${counts.pinned})`],
              ] as Array<[IosTransferFilter, string]>
            ).map(([id, label]) => {
              const active = filter === id;
              return (
                <TouchableOpacity
                  key={id}
                  onPress={() => setFilter(id)}
                  style={{
                    paddingHorizontal: 11,
                    paddingVertical: 6,
                    borderRadius: 999,
                    backgroundColor: active ? theme.accent : theme.bgSubtle,
                  }}
                >
                  <Text
                    style={{
                      fontSize: 12,
                      fontWeight: '700',
                      color: active ? theme.textOnAccent : theme.textSecondary,
                    }}
                  >
                    {label}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </ScrollView>
      </View>

      {/* Conversation & File Stream */}
      <View
        style={{
          backgroundColor: theme.bgCard,
          borderRadius: 16,
          padding: 13,
          gap: 11,
          borderWidth: 1,
          borderColor: theme.border,
        }}
      >
        {visibleItems.length === 0 ? (
          <View style={{ paddingVertical: 22, alignItems: 'center', gap: 6 }}>
            <Text style={{ fontSize: 14, fontWeight: '700', color: theme.textPrimary }}>
              {query || filter !== 'all' ? '没有匹配的互传记录' : '暂无互传消息或文件'}
            </Text>
            <Text
              style={{
                fontSize: 12,
                color: theme.textSecondary,
                textAlign: 'center',
                lineHeight: 1.45,
              }}
            >
              在下方输入文字或点击「发任意文件 / 发图影」，即可在电脑、Android 与 iOS 间实时加密互传。
            </Text>
          </View>
        ) : (
          visibleItems.map((item) => {
            const self = isSelfItem(item);
            const isSystemShare =
              item.sourceVia === 'system-share' || item.tags.includes('system-share');
            return (
              <View
                key={item.id}
                style={{
                  alignSelf: self ? 'flex-end' : 'flex-start',
                  width: '92%',
                  gap: 4,
                }}
                testID={`ios-transfer-item-${item.id}`}
              >
                <View
                  style={{
                    flexDirection: 'row',
                    alignItems: 'center',
                    justifyContent: self ? 'flex-end' : 'flex-start',
                    flexWrap: 'wrap',
                    gap: 6,
                  }}
                >
                  <Text style={{ fontSize: 11, fontWeight: '700', color: theme.textSecondary }}>
                    {item.senderDeviceName || platformBadgeText(item.senderPlatform)} ·{' '}
                    {platformBadgeText(item.senderPlatform)}
                  </Text>
                  {isSystemShare && (
                    <View
                      style={{
                        backgroundColor: theme.accentSoft,
                        borderWidth: 1,
                        borderColor: theme.accentBorder,
                        borderRadius: 999,
                        paddingHorizontal: 7,
                        paddingVertical: 1,
                      }}
                    >
                      <Text style={{ fontSize: 10, fontWeight: '700', color: theme.accent }}>
                        系统分享 · 发送
                      </Text>
                    </View>
                  )}
                  <Text style={{ fontSize: 10, color: theme.textTertiary }}>
                    {formatIosTime(item.createdAt)}
                  </Text>
                  {item.isPinned && (
                    <Text style={{ fontSize: 11, fontWeight: '800', color: theme.amber }}>★</Text>
                  )}
                  {item.syncSeq === 0 && (
                    <Text style={{ fontSize: 10, fontWeight: '700', color: theme.amber }}>
                      待同步
                    </Text>
                  )}
                </View>

                <View
                  style={{
                    backgroundColor: self ? theme.accentSoft : theme.bgSubtle,
                    borderRadius: 14,
                    padding: 11,
                    gap: 8,
                    borderWidth: 1,
                    borderColor: self ? theme.accentBorder : theme.border,
                  }}
                >
                  {item.replyPreview ? (
                    <View
                      style={{
                        borderLeftWidth: 3,
                        borderLeftColor: theme.accent,
                        paddingLeft: 8,
                        paddingVertical: 2,
                      }}
                    >
                      <Text
                        style={{ fontSize: 11, color: theme.textSecondary }}
                        numberOfLines={1}
                      >
                        {item.replyPreview}
                      </Text>
                    </View>
                  ) : null}

                  {(item.messageKind === 'image' || item.messageKind === 'video') && (
                    <View style={{ gap: 6 }}>
                      <TouchableOpacity
                        onPress={() =>
                          props.onJumpToMediaTab(
                            item.messageKind === 'video' ? 'video' : 'image',
                            item.linkedMediaId,
                          )
                        }
                      >
                        <IosTransferThumb item={item} client={client} theme={theme} />
                      </TouchableOpacity>
                      <TouchableOpacity
                        onPress={() =>
                          props.onJumpToMediaTab(
                            item.messageKind === 'video' ? 'video' : 'image',
                            item.linkedMediaId,
                          )
                        }
                        style={{
                          alignSelf: 'flex-start',
                          backgroundColor: theme.bgCard,
                          borderRadius: 8,
                          paddingHorizontal: 9,
                          paddingVertical: 5,
                          borderWidth: 1,
                          borderColor: theme.accentBorder,
                        }}
                      >
                        <Text style={{ fontSize: 11, fontWeight: '700', color: theme.accent }}>
                          ✓ 已自动存入{item.messageKind === 'video' ? '影院' : '相册'} · 点击查看
                        </Text>
                      </TouchableOpacity>
                    </View>
                  )}

                  {item.messageKind === 'file' && (
                    <View
                      style={{
                        flexDirection: 'row',
                        alignItems: 'center',
                        gap: 10,
                        backgroundColor: theme.bgCard,
                        borderRadius: 11,
                        padding: 10,
                        borderWidth: 1,
                        borderColor: theme.border,
                      }}
                    >
                      <View
                        style={{
                          width: 42,
                          height: 42,
                          borderRadius: 10,
                          backgroundColor: theme.accentSoft,
                          borderWidth: 1,
                          borderColor: theme.accentBorder,
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                      >
                        <Text style={{ fontSize: 10, fontWeight: '800', color: theme.accent }}>
                          {extBadge(item.originalFilename)}
                        </Text>
                      </View>
                      <View style={{ flex: 1 }}>
                        <Text
                          style={{ fontSize: 13, fontWeight: '700', color: theme.textPrimary }}
                          numberOfLines={1}
                        >
                          {item.originalFilename || '未命名文件'}
                        </Text>
                        <Text
                          style={{ fontSize: 11, color: theme.textSecondary, marginTop: 2 }}
                          numberOfLines={1}
                        >
                          {formatMobileBytes(item.plainSize)} · PSENC001
                          {item.sha256 ? ` · ${item.sha256.slice(0, 8)}` : ''}
                        </Text>
                      </View>
                      <TouchableOpacity
                        disabled={downloadingId === item.id}
                        onPress={() => void handleDownload(item)}
                        style={{
                          backgroundColor: theme.accent,
                          paddingHorizontal: 10,
                          paddingVertical: 7,
                          borderRadius: 9,
                        }}
                      >
                        <Text
                          style={{ fontSize: 11, fontWeight: '800', color: theme.textOnAccent }}
                        >
                          {downloadingId === item.id ? '解密中' : '保存'}
                        </Text>
                      </TouchableOpacity>
                    </View>
                  )}

                  {item.text ? (
                    <Text
                      style={{
                        fontSize: 13.5,
                        lineHeight: 1.45,
                        color: theme.textPrimary,
                      }}
                    >
                      {item.text}
                    </Text>
                  ) : null}

                  <View
                    style={{
                      flexDirection: 'row',
                      flexWrap: 'wrap',
                      gap: 10,
                      paddingTop: 4,
                      borderTopWidth: 1,
                      borderTopColor: theme.border,
                    }}
                  >
                    <TouchableOpacity onPress={() => setReplyTarget(item)}>
                      <Text style={{ fontSize: 11, fontWeight: '700', color: theme.textSecondary }}>
                        回复
                      </Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                      onPress={() =>
                        void props.onUpdateTransfer(item.id, { isPinned: !item.isPinned })
                      }
                    >
                      <Text
                        style={{
                          fontSize: 11,
                          fontWeight: '700',
                          color: item.isPinned ? theme.amber : theme.textSecondary,
                        }}
                      >
                        {item.isPinned ? '★ 已收藏' : '收藏'}
                      </Text>
                    </TouchableOpacity>

                    {item.text ? (
                      <TouchableOpacity
                        onPress={async () => {
                          await copyTextWithClipboard(item.text);
                          props.onToast('消息文本已复制');
                        }}
                      >
                        <Text
                          style={{ fontSize: 11, fontWeight: '700', color: theme.textSecondary }}
                        >
                          复制
                        </Text>
                      </TouchableOpacity>
                    ) : null}

                    <TouchableOpacity onPress={() => props.onInspectCipher(item.id)}>
                      <Text style={{ fontSize: 11, fontWeight: '700', color: theme.accent }}>
                        密文信封
                      </Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                      onPress={() => void props.onDeletePermanent(item.id)}
                      style={{ marginLeft: 'auto' }}
                    >
                      <Text style={{ fontSize: 11, fontWeight: '700', color: theme.danger }}>
                        销毁
                      </Text>
                    </TouchableOpacity>
                  </View>
                </View>
              </View>
            );
          })
        )}
      </View>

      {/* Composer Card */}
      <View
        style={{
          backgroundColor: theme.bgCard,
          borderRadius: 16,
          padding: 13,
          gap: 10,
          borderWidth: 1,
          borderColor: theme.border,
        }}
      >
        {replyTarget && (
          <View
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: theme.bgSubtle,
              borderRadius: 9,
              paddingHorizontal: 10,
              paddingVertical: 6,
              gap: 8,
            }}
          >
            <Text style={{ fontSize: 11, color: theme.textSecondary, flex: 1 }} numberOfLines={1}>
              回复 {summarizeReply(replyTarget)}
            </Text>
            <TouchableOpacity onPress={() => setReplyTarget(null)}>
              <Text style={{ fontSize: 12, fontWeight: '800', color: theme.textSecondary }}>✕</Text>
            </TouchableOpacity>
          </View>
        )}

        <View style={{ flexDirection: 'row', gap: 8 }}>
          <TextInput
            value={draft}
            onChangeText={setDraft}
            placeholder="输入文字消息、网址或文件说明..."
            style={{
              flex: 1,
              backgroundColor: theme.bgInput,
              borderWidth: 1,
              borderColor: theme.border,
              borderRadius: 11,
              paddingHorizontal: 12,
              paddingVertical: 9,
              fontSize: 13,
              color: theme.textPrimary,
            }}
            testID="ios-transfer-input"
          />
          <TouchableOpacity
            disabled={!draft.trim() || sending}
            onPress={() => void handleSendTextNow()}
            style={{
              backgroundColor: theme.accent,
              paddingHorizontal: 15,
              borderRadius: 11,
              alignItems: 'center',
              justifyContent: 'center',
              opacity: !draft.trim() || sending ? 0.5 : 1,
            }}
            testID="ios-transfer-send-btn"
          >
            {sending ? (
              <ActivityIndicator size="small" color={theme.textOnAccent} />
            ) : (
              <Text style={{ fontSize: 13, fontWeight: '800', color: theme.textOnAccent }}>
                发送
              </Text>
            )}
          </TouchableOpacity>
        </View>

        <View style={{ flexDirection: 'row', gap: 8 }}>
          <TouchableOpacity
            onPress={() => void handlePickAndSend('*/*')}
            style={{
              flex: 1,
              backgroundColor: theme.bgSubtle,
              paddingVertical: 9,
              borderRadius: 10,
              alignItems: 'center',
              borderWidth: 1,
              borderColor: theme.border,
            }}
            testID="ios-transfer-pick-file-btn"
          >
            <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textPrimary }}>
              + 发送任意文件 (PDF/ZIP/APK...)
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            onPress={() => void handlePickAndSend('image/*,video/*')}
            style={{
              flex: 1,
              backgroundColor: theme.accentSoft,
              paddingVertical: 9,
              borderRadius: 10,
              alignItems: 'center',
              borderWidth: 1,
              borderColor: theme.accentBorder,
            }}
            testID="ios-transfer-pick-media-btn"
          >
            <Text style={{ fontSize: 12, fontWeight: '700', color: theme.accent }}>
              + 发送图影 (自动入库)
            </Text>
          </TouchableOpacity>
        </View>
      </View>
    </View>
  );
}
