declare module 'react-native' {
  import type { ReactNode } from 'react';

  export interface StylePropRecord {
    [key: string]: string | number | undefined | Array<Record<string, string | number>>;
  }

  export type StyleProp = StylePropRecord | StyleProp[] | false | null | undefined;

  export interface BaseViewProps {
    children?: ReactNode;
    style?: StyleProp;
    testID?: string;
  }

  export function View(props: BaseViewProps): JSX.Element;
  export function SafeAreaView(props: BaseViewProps): JSX.Element;
  export function ScrollView(
    props: BaseViewProps & {
      contentContainerStyle?: StyleProp;
      horizontal?: boolean;
      showsHorizontalScrollIndicator?: boolean;
      showsVerticalScrollIndicator?: boolean;
    },
  ): JSX.Element;
  export function Text(
    props: BaseViewProps & {
      numberOfLines?: number;
      selectable?: boolean;
      onPress?: () => void;
    },
  ): JSX.Element;
  export function TouchableOpacity(
    props: BaseViewProps & {
      onPress?: () => void;
      disabled?: boolean;
      activeOpacity?: number;
    },
  ): JSX.Element;
  export function TextInput(props: {
    value?: string;
    onChangeText?: (value: string) => void;
    placeholder?: string;
    placeholderTextColor?: string;
    secureTextEntry?: boolean;
    multiline?: boolean;
    autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters';
    keyboardType?: 'default' | 'url' | 'email-address' | 'numeric';
    style?: StyleProp;
    testID?: string;
  }): JSX.Element;
  export function Image(props: {
    source: { uri: string };
    style?: StyleProp;
    resizeMode?: 'cover' | 'contain' | 'stretch' | 'center';
  }): JSX.Element;
  export function Modal(props: {
    visible: boolean;
    animationType?: 'none' | 'slide' | 'fade';
    transparent?: boolean;
    onRequestClose?: () => void;
    children?: ReactNode;
  }): JSX.Element;
  export function Switch(props: {
    value: boolean;
    onValueChange?: (next: boolean) => void;
    trackColor?: { false?: string; true?: string };
    thumbColor?: string;
  }): JSX.Element;
  export function ActivityIndicator(props: {
    size?: 'small' | 'large';
    color?: string;
  }): JSX.Element;

  export const StyleSheet: {
    create<T extends Record<string, StylePropRecord>>(styles: T): T;
  };

  export const Platform: {
    OS: 'ios' | 'android' | 'web';
  };
}
