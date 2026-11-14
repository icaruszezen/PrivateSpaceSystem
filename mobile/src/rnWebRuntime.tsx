import React, { type CSSProperties, type ReactNode } from 'react';

type StyleInput =
  | Record<string, unknown>
  | StyleInput[]
  | false
  | null
  | undefined;

const UNITLESS_KEYS = new Set([
  'flex',
  'flexGrow',
  'flexShrink',
  'opacity',
  'zIndex',
  'fontWeight',
  'lineHeight',
  'aspectRatio',
]);

function flattenStyle(style: StyleInput): CSSProperties {
  if (!style) return {};
  if (Array.isArray(style)) {
    return Object.assign({}, ...style.map(flattenStyle));
  }
  const out: Record<string, unknown> = {};
  const raw = style as Record<string, unknown>;

  for (const [key, val] of Object.entries(raw)) {
    if (val === undefined || val === null) continue;
    if (key === 'paddingHorizontal') {
      out.paddingLeft = typeof val === 'number' ? `${val}px` : val;
      out.paddingRight = typeof val === 'number' ? `${val}px` : val;
    } else if (key === 'paddingVertical') {
      out.paddingTop = typeof val === 'number' ? `${val}px` : val;
      out.paddingBottom = typeof val === 'number' ? `${val}px` : val;
    } else if (key === 'marginHorizontal') {
      out.marginLeft = typeof val === 'number' ? `${val}px` : val;
      out.marginRight = typeof val === 'number' ? `${val}px` : val;
    } else if (key === 'marginVertical') {
      out.marginTop = typeof val === 'number' ? `${val}px` : val;
      out.marginBottom = typeof val === 'number' ? `${val}px` : val;
    } else if (key === 'transform' && Array.isArray(val)) {
      const parts: string[] = [];
      for (const entry of val as Array<Record<string, string | number>>) {
        for (const [tKey, tVal] of Object.entries(entry)) {
          parts.push(`${tKey}(${tVal})`);
        }
      }
      out.transform = parts.join(' ');
    } else if (typeof val === 'number' && !UNITLESS_KEYS.has(key)) {
      out[key] = `${val}px`;
    } else {
      out[key] = val;
    }
  }

  return out as CSSProperties;
}

export const Platform = {
  OS: 'ios' as const,
};

export const StyleSheet = {
  create<T extends Record<string, Record<string, unknown>>>(styles: T): T {
    return styles;
  },
};

export function View(props: {
  children?: ReactNode;
  style?: StyleInput;
  testID?: string;
}): React.JSX.Element {
  return (
    <div
      data-testid={props.testID}
      style={{
        display: 'flex',
        flexDirection: 'column',
        boxSizing: 'border-box',
        minWidth: 0,
        ...flattenStyle(props.style),
      }}
    >
      {props.children}
    </div>
  );
}

export function SafeAreaView(props: {
  children?: ReactNode;
  style?: StyleInput;
  testID?: string;
}): React.JSX.Element {
  return (
    <div
      data-testid={props.testID}
      style={{
        display: 'flex',
        flexDirection: 'column',
        boxSizing: 'border-box',
        width: '100%',
        height: '100%',
        minHeight: 0,
        paddingTop: 'env(safe-area-inset-top, 0px)',
        paddingBottom: 'env(safe-area-inset-bottom, 0px)',
        ...flattenStyle(props.style),
      }}
    >
      {props.children}
    </div>
  );
}

export function ScrollView(props: {
  children?: ReactNode;
  style?: StyleInput;
  contentContainerStyle?: StyleInput;
  horizontal?: boolean;
  showsHorizontalScrollIndicator?: boolean;
  showsVerticalScrollIndicator?: boolean;
  testID?: string;
}): React.JSX.Element {
  return (
    <div
      data-testid={props.testID}
      className="rn-scroll-view"
      style={{
        display: 'flex',
        flexDirection: props.horizontal ? 'row' : 'column',
        overflowX: props.horizontal ? 'auto' : 'hidden',
        overflowY: props.horizontal ? 'hidden' : 'auto',
        WebkitOverflowScrolling: 'touch',
        boxSizing: 'border-box',
        minHeight: 0,
        ...flattenStyle(props.style),
      }}
    >
      <div
        style={{
          display: 'flex',
          flexDirection: props.horizontal ? 'row' : 'column',
          boxSizing: 'border-box',
          minWidth: props.horizontal ? 'max-content' : 0,
          width: props.horizontal ? 'auto' : '100%',
          ...flattenStyle(props.contentContainerStyle),
        }}
      >
        {props.children}
      </div>
    </div>
  );
}

export function Text(props: {
  children?: ReactNode;
  style?: StyleInput;
  numberOfLines?: number;
  selectable?: boolean;
  onPress?: () => void;
  testID?: string;
}): React.JSX.Element {
  const clampStyles: CSSProperties =
    props.numberOfLines === 1
      ? {
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }
      : props.numberOfLines && props.numberOfLines > 1
        ? {
            display: '-webkit-box',
            WebkitLineClamp: props.numberOfLines,
            WebkitBoxOrient: 'vertical',
            overflow: 'hidden',
          }
        : {};

  return (
    <span
      data-testid={props.testID}
      onClick={props.onPress}
      style={{
        boxSizing: 'border-box',
        userSelect: props.selectable ? 'text' : 'none',
        cursor: props.onPress ? 'pointer' : undefined,
        ...clampStyles,
        ...flattenStyle(props.style),
      }}
    >
      {props.children}
    </span>
  );
}

export function TouchableOpacity(props: {
  children?: ReactNode;
  style?: StyleInput;
  onPress?: () => void;
  disabled?: boolean;
  activeOpacity?: number;
  testID?: string;
}): React.JSX.Element {
  return (
    <button
      type="button"
      data-testid={props.testID}
      disabled={props.disabled}
      onClick={props.disabled ? undefined : props.onPress}
      className="rn-touchable"
      style={{
        display: 'flex',
        flexDirection: 'column',
        background: 'transparent',
        border: 'none',
        padding: 0,
        margin: 0,
        font: 'inherit',
        textAlign: 'left',
        cursor: props.disabled ? 'not-allowed' : 'pointer',
        opacity: props.disabled ? 0.5 : 1,
        boxSizing: 'border-box',
        ...flattenStyle(props.style),
      }}
    >
      {props.children}
    </button>
  );
}

export function TextInput(props: {
  value?: string;
  onChangeText?: (value: string) => void;
  placeholder?: string;
  placeholderTextColor?: string;
  secureTextEntry?: boolean;
  multiline?: boolean;
  autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters';
  keyboardType?: 'default' | 'url' | 'email-address' | 'numeric';
  style?: StyleInput;
  testID?: string;
}): React.JSX.Element {
  const baseStyle: CSSProperties = {
    font: 'inherit',
    outline: 'none',
    boxSizing: 'border-box',
    width: '100%',
    ...flattenStyle(props.style),
  };

  if (props.multiline) {
    return (
      <textarea
        data-testid={props.testID}
        value={props.value ?? ''}
        placeholder={props.placeholder}
        onChange={(e) => props.onChangeText?.(e.target.value)}
        style={{
          ...baseStyle,
          resize: 'vertical',
        }}
      />
    );
  }

  return (
    <input
      data-testid={props.testID}
      type={props.secureTextEntry ? 'password' : 'text'}
      value={props.value ?? ''}
      placeholder={props.placeholder}
      autoCapitalize={props.autoCapitalize}
      onChange={(e) => props.onChangeText?.(e.target.value)}
      style={baseStyle}
    />
  );
}

export function Image(props: {
  source: { uri: string };
  style?: StyleInput;
  resizeMode?: 'cover' | 'contain' | 'stretch' | 'center';
}): React.JSX.Element {
  const objectFit =
    props.resizeMode === 'contain'
      ? 'contain'
      : props.resizeMode === 'stretch'
        ? 'fill'
        : 'cover';

  return (
    <img
      src={props.source.uri}
      alt=""
      loading="lazy"
      style={{
        display: 'block',
        objectFit,
        boxSizing: 'border-box',
        ...flattenStyle(props.style),
      }}
    />
  );
}

export function Modal(props: {
  visible: boolean;
  animationType?: 'none' | 'slide' | 'fade';
  transparent?: boolean;
  onRequestClose?: () => void;
  children?: ReactNode;
}): React.JSX.Element | null {
  if (!props.visible) return null;
  return (
    <div
      className={`rn-modal-overlay ${props.animationType === 'fade' ? 'is-fade' : 'is-slide'}`}
      style={{
        position: 'absolute',
        inset: 0,
        zIndex: 60,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'flex-end',
        backgroundColor: props.transparent ? 'rgba(12, 16, 17, 0.52)' : 'transparent',
        backdropFilter: props.transparent ? 'blur(6px)' : undefined,
      }}
    >
      {props.children}
    </div>
  );
}

export function Switch(props: {
  value: boolean;
  onValueChange?: (next: boolean) => void;
  trackColor?: { false?: string; true?: string };
}): React.JSX.Element {
  const activeBg = props.trackColor?.true ?? '#266454';
  const inactiveBg = props.trackColor?.false ?? '#D2D6D4';

  return (
    <button
      type="button"
      role="switch"
      aria-checked={props.value}
      onClick={() => props.onValueChange?.(!props.value)}
      style={{
        width: '46px',
        height: '28px',
        borderRadius: '999px',
        border: 'none',
        padding: '2px',
        backgroundColor: props.value ? activeBg : inactiveBg,
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: props.value ? 'flex-end' : 'flex-start',
        transition: 'background-color 160ms ease',
      }}
    >
      <span
        style={{
          width: '24px',
          height: '24px',
          borderRadius: '50%',
          backgroundColor: '#FFFFFF',
          boxShadow: '0 1px 3px rgba(0,0,0,0.22)',
        }}
      />
    </button>
  );
}

export function ActivityIndicator(props: {
  size?: 'small' | 'large';
  color?: string;
}): React.JSX.Element {
  const dim = props.size === 'large' ? 26 : 16;
  const stroke = props.color ?? '#266454';
  return (
    <span
      style={{
        width: `${dim}px`,
        height: `${dim}px`,
        borderRadius: '50%',
        border: `2.5px solid rgba(128,128,128,0.25)`,
        borderTopColor: stroke,
        display: 'inline-block',
        animation: 'pssSpin 0.75s linear infinite',
      }}
    />
  );
}
