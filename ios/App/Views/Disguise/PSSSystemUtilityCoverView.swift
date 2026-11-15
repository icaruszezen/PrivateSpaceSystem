import PrivateSpaceKit
import SwiftUI

struct PSSSystemUtilityCoverView: View {
    @Bindable var store: VaultStore
    @Environment(\.colorScheme) private var colorScheme

    @State private var expressionText: String = "4096"
    @State private var resultDecimal: String = "4,096"
    @State private var resultHex: String = "0x1000"
    @State private var resultIec: String = "4.00 KiB"
    @State private var tapDates: [Date] = []

    private let keypadRows: [[String]] = [
        ["AC", "0x", "KiB", "/"],
        ["7", "8", "9", "*"],
        ["4", "5", "6", "-"],
        ["1", "2", "3", "+"],
        ["MiB", "0", ".", "="]
    ]

    var body: some View {
        NavigationStack {
            VStack(spacing: 14) {
                // Expression & Radix Readout Card
                VStack(alignment: .trailing, spacing: 10) {
                    TextField("输入算式或十六进制", text: $expressionText)
                        .font(.system(.subheadline, design: .monospaced))
                        .multilineTextAlignment(.trailing)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: expressionText) { _, next in
                            recomputeDisplay(next)
                        }

                    Text(resultDecimal)
                        .font(.system(size: 30, weight: .bold, design: .monospaced))
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)

                    Divider()

                    HStack {
                        Label(resultHex, systemImage: "number")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Label(resultIec, systemImage: "internaldrive")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(16)
                .background(
                    MineralPineTheme.cardBackground(for: colorScheme),
                    in: RoundedRectangle(cornerRadius: 18)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
                )

                // Tactile 5x4 Keypad
                VStack(spacing: 8) {
                    ForEach(keypadRows, id: \.self) { row in
                        HStack(spacing: 8) {
                            ForEach(row, id: \.self) { key in
                                Button {
                                    handleKeyTap(key)
                                } label: {
                                    Text(key)
                                        .font(.system(.body, design: .monospaced).weight(.semibold))
                                        .frame(maxWidth: .infinity)
                                        .frame(height: 48)
                                        .background(
                                            key == "="
                                                ? MineralPineTheme.primaryAccent(for: colorScheme)
                                                : MineralPineTheme.cardBackground(for: colorScheme),
                                            in: RoundedRectangle(cornerRadius: 12)
                                        )
                                        .foregroundStyle(key == "=" ? Color.white : Color.primary)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 12)
                                                .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
                                        )
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }

                Spacer(minLength: 4)

                // Version Badge (supports 5-tap rapid gesture unlock)
                Button {
                    handleVersionBadgeTap()
                } label: {
                    Text("PSS Core v\(store.currentAppVersion) (Build #\(store.currentAppBuild)) · Personal System Service")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 18)
            .padding(.top, 10)
            .padding(.bottom, 12)
            .navigationTitle("PSS")
            .navigationBarTitleDisplayMode(.inline)
        }
        .onAppear {
            recomputeDisplay(expressionText)
        }
    }

    private func handleKeyTap(_ key: String) {
        switch key {
        case "AC":
            expressionText = ""
            recomputeDisplay("")
        case "=":
            if store.attemptDisguiseUnlock(input: expressionText) {
                return
            }
            recomputeDisplay(expressionText)
            if resultDecimal != "—" {
                expressionText = resultDecimal.replacingOccurrences(of: ",", with: "")
            }
        case "KiB", "MiB":
            expressionText += " \(key)"
        case "+", "-", "*", "/":
            expressionText += " \(key) "
        default:
            expressionText = (expressionText == "0") ? key : (expressionText + key)
        }
    }

    private func handleVersionBadgeTap() {
        guard store.disguiseGestureUnlockEnabled else { return }
        let now = Date()
        tapDates = tapDates.filter { now.timeIntervalSince($0) <= 2.4 } + [now]
        if tapDates.count >= 5 {
            tapDates.removeAll()
            store.isDisguiseCoverActive = false
        }
    }

    private func recomputeDisplay(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            resultDecimal = "0"
            resultHex = "0x0"
            resultIec = "0 B"
            return
        }

        let normalized = trimmed
            .replacingOccurrences(of: "KiB", with: "*1024", options: .caseInsensitive)
            .replacingOccurrences(of: "MiB", with: "*1048576", options: .caseInsensitive)
            .replacingOccurrences(of: "GiB", with: "*1073741824", options: .caseInsensitive)

        if let val = evaluateSimpleExpression(normalized), val.isFinite {
            let formatter = NumberFormatter()
            formatter.numberStyle = .decimal
            formatter.maximumFractionDigits = 4
            resultDecimal = formatter.string(from: NSNumber(value: val)) ?? "\(val)"
            let intVal = Int64(val.rounded())
            resultHex = intVal >= 0 ? "0x" + String(intVal, radix: 16, uppercase: true) : "-0x" + String(-intVal, radix: 16, uppercase: true)
            resultIec = VaultFormatters.formatBytes(Int(max(0, intVal)))
        } else {
            resultDecimal = "—"
            resultHex = "—"
            resultIec = "—"
        }
    }

    private func evaluateSimpleExpression(_ expr: String) -> Double? {
        if expr.lowercased().hasPrefix("0x"),
           let hexInt = UInt64(expr.dropFirst(2), radix: 16) {
            return Double(hexInt)
        }
        let allowed = CharacterSet(charactersIn: "0123456789.+-*/() ")
        guard expr.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        let mathExpr = NSExpression(format: expr)
        return (mathExpr.expressionValue(with: nil, context: nil) as? NSNumber)?.doubleValue
    }
}
