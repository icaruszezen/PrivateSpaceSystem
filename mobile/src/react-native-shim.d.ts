declare module 'react-native' {
  import type { ReactNode } from 'react';

  export interface StylePropRecord {
    [key: string]: string | number | undefined;
  }

  export type StyleProp = StylePropRecord | StylePropRecord[] | false | null | undefined;

  export interface BaseViewProps {
    children?: ReactNode;
    style?: StyleProp;
    testID?: string;
  }

  export function View(props: BaseViewProps): JSX.Element;
  export function SafeAreaView(props: BaseViewProps): JSX.Element;
  export function ScrollView(
    props: BaseViewProps & { contentContainerStyle?: StyleProp; horizontal?: boolean },
  ): JSX.Element;
  export function Text(
    props: BaseViewProps & { numberOfLines?: number; selectable?: boolean },
  ): JSX.Element;
  export function TouchableOpacity(
    props: BaseViewProps & { onPress?: () => void; disabled?: boolean; activeOpacity?: number },
  ): JSX.Element;
  export function TextInput(props: {
    value?: string;
    onChangeText?: (value: string) => void;
    placeholder?: string;
    placeholderTextColor?: string;
    secureTextEntry?: boolean;
    autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters';
    style?: StyleProp;
  }): JSX.Element;
  export function Image(props: {
    source: { uri: string };
    style?: StyleProp;
    resizeMode?: 'cover' | 'contain' | 'stretch' | 'center';
  }): JSX.Element;

  export const StyleSheet: {
    create<T extends Record<string, StylePropRecord>>(styles: T): T;
  };

  export const Platform: {
    OS: 'ios' | 'android' | 'web';
  };
}
