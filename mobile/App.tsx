import { useEffect, useMemo, useState } from 'react';
import {
  Image,
  Platform,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { PrivateSpaceMobileClient, type MobileVaultSnapshot } from './src/syncClient';

type MobileTab = 'notes' | 'passwords' | 'images' | 'videos' | 'sync';

export default function PrivateSpaceMobileApp() {
  const [serverUrl, setServerUrl] = useState('https://vault.example.internal');
  const [masterPassword, setMasterPassword] = useState('');
  const [unlocked, setUnlocked] = useState(false);
  const [activeTab, setActiveTab] = useState<MobileTab>('passwords');
  const [snapshot, setSnapshot] = useState<MobileVaultSnapshot | null>(null);
  const [statusMessage, setStatusMessage] = useState<string>('等待连接自部署私密空间节点');
  const [tick, setTick] = useState(() => Date.now());

  const client = useMemo(
    () =>
      new PrivateSpaceMobileClient({
        baseUrl: serverUrl,
        platform: Platform.OS === 'ios' ? 'ios' : 'android',
        deviceName: Platform.OS === 'ios' ? 'iPhone (PrivateSpace iOS)' : 'Android (PrivateSpace)',
      }),
    [serverUrl],
  );

  useEffect(() => {
    const timer = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleUnlockAndSync = async () => {
    try {
      setStatusMessage('正在验证管理员主密码并拉取增量游标...');
      await client.login(masterPassword);
      const { snapshot: next } = await client.syncDelta();
      setSnapshot(next);
      setUnlocked(true);
      setMasterPassword('');
      setStatusMessage(`已同步至游标 #${next.lastSyncSeq}`);
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : '连接失败');
    }
  };

  const handleManualSync = async () => {
    try {
      const { snapshot: next, delta } = await client.syncDelta();
      setSnapshot(next);
      setStatusMessage(
        `增量同步完成：新增/更新 ${delta.items.length} 项 · 游标 #${next.lastSyncSeq}`,
      );
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : '同步失败');
    }
  };

  if (!unlocked || !snapshot) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.authCard}>
          <Text style={styles.brandBadge}>AES-256-GCM · 自部署端到端静态加密</Text>
          <Text style={styles.title}>PrivateSpace 移动空间</Text>
          <Text style={styles.subtitle}>支持文本、密码 (TOTP)、加密原图与流式视频多端同步</Text>

          <Text style={styles.label}>自部署服务器地址</Text>
          <TextInput
            value={serverUrl}
            onChangeText={setServerUrl}
            autoCapitalize="none"
            placeholder="https://vault.yourdomain.com"
            style={styles.input}
          />

          <Text style={styles.label}>唯一管理员主密码</Text>
          <TextInput
            value={masterPassword}
            onChangeText={setMasterPassword}
            secureTextEntry
            placeholder="输入管理员主密码解锁空间"
            style={styles.input}
          />

          <TouchableOpacity style={styles.primaryBtn} onPress={handleUnlockAndSync}>
            <Text style={styles.primaryBtnText}>解锁并同步空间</Text>
          </TouchableOpacity>

          <Text style={styles.statusFoot}>{statusMessage}</Text>
        </View>
      </SafeAreaView>
    );
  }

  const passwords = Object.values(snapshot.passwords).filter((p) => !p.isTrashed);
  const images = Object.values(snapshot.media).filter(
    (m) => m.itemType === 'image' && !m.isTrashed,
  );
  const videos = Object.values(snapshot.media).filter(
    (m) => m.itemType === 'video' && !m.isTrashed,
  );
  const notes = Object.values(snapshot.notes).filter((n) => !n.isTrashed);

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <View>
          <Text style={styles.headerTitle}>PrivateSpace</Text>
          <Text style={styles.headerMeta}>{statusMessage}</Text>
        </View>
        <TouchableOpacity style={styles.syncPill} onPress={handleManualSync}>
          <Text style={styles.syncPillText}>立即同步</Text>
        </TouchableOpacity>
      </View>

      <ScrollView style={styles.body}>
        {activeTab === 'passwords' &&
          passwords.map((pw) => {
            const totp = pw.totpSecret ? client.computeTotp(pw.totpSecret, tick) : null;
            return (
              <View key={pw.id} style={styles.itemCard}>
                <Text style={styles.itemTitle}>{pw.title}</Text>
                <Text style={styles.itemSub}>{pw.username || pw.url || '无用户名'}</Text>
                {totp && (
                  <View style={styles.totpRow}>
                    <Text style={styles.totpCode}>
                      {totp.code.slice(0, 3)} {totp.code.slice(3)}
                    </Text>
                    <Text style={styles.totpRemain}>{totp.remainingSeconds}s</Text>
                  </View>
                )}
              </View>
            );
          })}

        {activeTab === 'images' && (
          <View style={styles.mediaGrid}>
            {images.map((img) => (
              <View key={img.id} style={styles.mediaTile}>
                <Image
                  source={{ uri: client.getThumbnailUrl(img.id) }}
                  style={styles.mediaThumb}
                  resizeMode="cover"
                />
                <Text style={styles.mediaCaption} numberOfLines={1}>
                  {img.title}
                </Text>
              </View>
            ))}
          </View>
        )}

        {activeTab === 'videos' &&
          videos.map((vid) => (
            <View key={vid.id} style={styles.itemCard}>
              <Text style={styles.itemTitle}>{vid.title}</Text>
              <Text style={styles.itemSub}>
                HTTP 206 分块解密流 · {vid.width}×{vid.height} · {client.getStreamUrl(vid.id)}
              </Text>
            </View>
          ))}

        {activeTab === 'notes' &&
          notes.map((note) => (
            <View key={note.id} style={styles.itemCard}>
              <Text style={styles.itemTitle}>{note.title}</Text>
              <Text style={styles.itemSub} numberOfLines={2}>
                {note.excerpt}
              </Text>
            </View>
          ))}
      </ScrollView>

      <View style={styles.tabBar}>
        {(
          [
            ['passwords', `密码 (${passwords.length})`],
            ['images', `图片 (${images.length})`],
            ['videos', `视频 (${videos.length})`],
            ['notes', `笔记 (${notes.length})`],
          ] as const
        ).map(([id, label]) => (
          <TouchableOpacity
            key={id}
            style={activeTab === id ? styles.tabItemActive : styles.tabItem}
            onPress={() => setActiveTab(id)}
          >
            <Text style={activeTab === id ? styles.tabTextActive : styles.tabText}>{label}</Text>
          </TouchableOpacity>
        ))}
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#F8F7F4' },
  authCard: { margin: 24, padding: 24, backgroundColor: '#FFFFFF', borderRadius: 16 },
  brandBadge: { fontSize: 12, color: '#266454', fontWeight: '600', marginBottom: 8 },
  title: { fontSize: 24, fontWeight: '700', color: '#171918', marginBottom: 6 },
  subtitle: { fontSize: 13, color: '#646A67', marginBottom: 20 },
  label: { fontSize: 12, fontWeight: '600', color: '#393E3C', marginBottom: 6 },
  input: {
    borderWidth: 1,
    borderColor: '#DFE2DF',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    marginBottom: 14,
    color: '#171918',
  },
  primaryBtn: {
    backgroundColor: '#266454',
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: 'center',
  },
  primaryBtnText: { color: '#FFFFFF', fontWeight: '600', fontSize: 15 },
  statusFoot: { marginTop: 12, fontSize: 12, color: '#646A67', textAlign: 'center' },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 18,
    paddingVertical: 14,
    borderBottomWidth: 1,
    borderBottomColor: '#E7E9E6',
  },
  headerTitle: { fontSize: 18, fontWeight: '700', color: '#171918' },
  headerMeta: { fontSize: 12, color: '#646A67', marginTop: 2 },
  syncPill: {
    backgroundColor: '#E8F2EF',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 999,
  },
  syncPillText: { color: '#266454', fontSize: 12, fontWeight: '600' },
  body: { flex: 1, padding: 16 },
  itemCard: {
    backgroundColor: '#FFFFFF',
    padding: 14,
    borderRadius: 12,
    marginBottom: 10,
    borderWidth: 1,
    borderColor: '#E7E9E6',
  },
  itemTitle: { fontSize: 15, fontWeight: '600', color: '#171918' },
  itemSub: { fontSize: 12, color: '#646A67', marginTop: 4 },
  totpRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginTop: 10,
    paddingTop: 8,
    borderTopWidth: 1,
    borderTopColor: '#F0F1EF',
  },
  totpCode: { fontSize: 18, fontWeight: '700', color: '#266454', letterSpacing: 1.5 },
  totpRemain: { fontSize: 12, color: '#646A67' },
  mediaGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: 10 },
  mediaTile: { width: '48%', backgroundColor: '#FFFFFF', borderRadius: 10, overflow: 'hidden' },
  mediaThumb: { width: '100%', height: 120, backgroundColor: '#E7E9E6' },
  mediaCaption: { fontSize: 12, padding: 8, color: '#171918' },
  tabBar: {
    flexDirection: 'row',
    borderTopWidth: 1,
    borderTopColor: '#E7E9E6',
    backgroundColor: '#FFFFFF',
    paddingVertical: 8,
  },
  tabItem: { flex: 1, alignItems: 'center', paddingVertical: 6 },
  tabItemActive: { flex: 1, alignItems: 'center', paddingVertical: 6 },
  tabText: { fontSize: 12, color: '#646A67' },
  tabTextActive: { fontSize: 12, color: '#266454', fontWeight: '700' },
});
