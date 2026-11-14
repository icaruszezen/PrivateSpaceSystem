import React, { useRef, useState } from 'react';
import { Text, TouchableOpacity, View } from 'react-native';
import type { IosThemeTokens } from './iosTheme';

export async function copyTextWithClipboard(text: string): Promise<boolean> {
  if (!text) return false;
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fallback below
  }
  try {
    if (typeof document !== 'undefined') {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      document.body.removeChild(area);
      return true;
    }
  } catch {
    // ignore
  }
  return false;
}

export async function computeSha256Hex(bytes: Uint8Array): Promise<string | undefined> {
  try {
    if (globalThis.crypto?.subtle) {
      const digest = await globalThis.crypto.subtle.digest(
        'SHA-256',
        bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
      );
      return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    }
  } catch {
    // ignore on plain HTTP non-secure context
  }
  return undefined;
}

export function pickLocalMediaFiles(
  accept: string,
  multiple = true,
): Promise<Array<{ name: string; type: string; bytes: Uint8Array }>> {
  return new Promise((resolve) => {
    if (typeof document === 'undefined') {
      resolve([]);
      return;
    }
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.multiple = multiple;
    input.style.display = 'none';
    document.body.appendChild(input);

    input.onchange = async () => {
      const fileList = Array.from(input.files ?? []);
      document.body.removeChild(input);
      const loaded: Array<{ name: string; type: string; bytes: Uint8Array }> = [];
      for (const f of fileList) {
        const buf = await f.arrayBuffer();
        loaded.push({
          name: f.name,
          type: f.type || 'application/octet-stream',
          bytes: new Uint8Array(buf),
        });
      }
      resolve(loaded);
    };

    input.oncancel = () => {
      if (input.parentNode) document.body.removeChild(input);
      resolve([]);
    };

    input.click();
  });
}

/**
 * Circular countdown ring for RFC 6238 2FA TOTP codes.
 */
export function IosTotpRing(props: {
  progress: number;
  remainingSeconds: number;
  theme: IosThemeTokens;
}): React.JSX.Element {
  const strokeColor =
    props.remainingSeconds <= 5 ? props.theme.danger : props.theme.accent;

  if (typeof document !== 'undefined') {
    const r = 9.5;
    const c = 2 * Math.PI * r;
    const dashOffset = c * Math.min(1, Math.max(0, props.progress));
    return (
      <div
        style={{
          position: 'relative',
          width: '24px',
          height: '24px',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}
      >
        <svg width="24" height="24" viewBox="0 0 24 24" style={{ transform: 'rotate(-90deg)' }}>
          <circle
            cx="12"
            cy="12"
            r={r}
            fill="none"
            stroke={props.theme.borderStrong}
            strokeWidth="2.4"
            opacity={0.45}
          />
          <circle
            cx="12"
            cy="12"
            r={r}
            fill="none"
            stroke={strokeColor}
            strokeWidth="2.4"
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={dashOffset}
          />
        </svg>
        <span
          style={{
            position: 'absolute',
            fontSize: '9px',
            fontWeight: 700,
            color: props.theme.textSecondary,
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {props.remainingSeconds}
        </span>
      </div>
    );
  }

  return (
    <View
      style={{
        width: 24,
        height: 24,
        borderRadius: 12,
        borderWidth: 2,
        borderColor: strokeColor,
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Text style={{ fontSize: 9, fontWeight: '700', color: strokeColor }}>
        {props.remainingSeconds}
      </Text>
    </View>
  );
}

/**
 * Authenticated HTTP 206 Partial Content Video Stream Surface for iOS Safari / AVPlayer WebKit.
 */
export function IosStreamingVideoSurface(props: {
  streamUrl: string;
  posterUrl?: string;
  theme: IosThemeTokens;
}): React.JSX.Element {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [rate, setRate] = useState(1);

  if (typeof document !== 'undefined') {
    const skip = (sec: number) => {
      if (!videoRef.current) return;
      videoRef.current.currentTime = Math.max(0, videoRef.current.currentTime + sec);
    };

    const applyRate = (nextRate: number) => {
      setRate(nextRate);
      if (videoRef.current) {
        videoRef.current.playbackRate = nextRate;
      }
    };

    return (
      <View style={{ gap: 10 }}>
        <div
          style={{
            width: '100%',
            borderRadius: '14px',
            overflow: 'hidden',
            backgroundColor: '#07090A',
            border: `1px solid ${props.theme.border}`,
          }}
        >
          <video
            ref={videoRef}
            src={props.streamUrl}
            poster={props.posterUrl}
            controls
            playsInline
            preload="metadata"
            style={{
              width: '100%',
              maxHeight: '236px',
              display: 'block',
              backgroundColor: '#000000',
            }}
          />
        </div>

        <View
          style={{
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 6,
          }}
        >
          <View style={{ flexDirection: 'row', gap: 5, flexShrink: 0 }}>
            <TouchableOpacity
              onPress={() => skip(-10)}
              style={{
                paddingHorizontal: 9,
                paddingVertical: 5,
                borderRadius: 8,
                backgroundColor: props.theme.bgSubtle,
                flexShrink: 0,
              }}
            >
              <Text
                style={{ fontSize: 11, fontWeight: '700', color: props.theme.textPrimary }}
                numberOfLines={1}
              >
                ↺ 10s
              </Text>
            </TouchableOpacity>
            <TouchableOpacity
              onPress={() => skip(10)}
              style={{
                paddingHorizontal: 9,
                paddingVertical: 5,
                borderRadius: 8,
                backgroundColor: props.theme.bgSubtle,
                flexShrink: 0,
              }}
            >
              <Text
                style={{ fontSize: 11, fontWeight: '700', color: props.theme.textPrimary }}
                numberOfLines={1}
              >
                10s ↻
              </Text>
            </TouchableOpacity>
          </View>

          <View style={{ flexDirection: 'row', gap: 4, flexShrink: 0 }}>
            {[0.75, 1, 1.25, 1.5, 2].map((r) => (
              <TouchableOpacity
                key={r}
                onPress={() => applyRate(r)}
                style={{
                  paddingHorizontal: 7,
                  paddingVertical: 5,
                  borderRadius: 999,
                  backgroundColor: rate === r ? props.theme.accent : props.theme.bgSubtle,
                  flexShrink: 0,
                }}
              >
                <Text
                  style={{
                    fontSize: 11,
                    fontWeight: '700',
                    color: rate === r ? props.theme.textOnAccent : props.theme.textSecondary,
                  }}
                  numberOfLines={1}
                >
                  {r}×
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>
      </View>
    );
  }

  return (
    <View
      style={{
        padding: 16,
        borderRadius: 12,
        backgroundColor: props.theme.bgSubtle,
      }}
    >
      <Text style={{ fontSize: 12, color: props.theme.textSecondary }} selectable>
        AVPlayer HTTP 206 流地址：{props.streamUrl}
      </Text>
    </View>
  );
}
