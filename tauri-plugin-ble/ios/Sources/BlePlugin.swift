import CoreBluetooth
import Tauri
import UIKit

// MARK: - Constants

private let kServiceUUID = CBUUID(string: "7D2EA8B0-F94C-4B6D-9C8F-3A1B5E6D0F2A")
private let kCharacteristicUUID = CBUUID(string: "7D2EA8B1-F94C-4B6D-9C8F-3A1B5E6D0F2A")

// MARK: - Plugin

class BlePlugin: Plugin {
    private var peripheralManager: CBPeripheralManager?
    private var centralManager: CBCentralManager?
    private var peripheralDelegate: PeripheralManagerDelegate?
    private var centralDelegate: CentralManagerDelegate?

    // Advertising state
    private var senderInfoData: Data?
    private var senderInfoCharacteristic: CBMutableCharacteristic?
    private var isAdvertising = false

    // Scanning state
    private var isScanning = false
    private var targetCodeHash: Data?

    // GATT read state
    private var pendingReadInvoke: Invoke?
    private var connectedPeripheral: CBPeripheral?
    private var gattDelegate: GattClientDelegate?

    // MARK: - Advertising (Sender)

    @objc func startAdvertising(_ invoke: Invoke) {
        guard !isAdvertising else {
            invoke.reject("Already advertising")
            return
        }

        guard let args = try? invoke.parseArgs(StartAdvertisingArgs.self) else {
            invoke.reject("Invalid arguments")
            return
        }

        senderInfoData = args.senderInfoJson.data(using: .utf8)

        // Create the GATT characteristic (read-only, containing sender info JSON)
        senderInfoCharacteristic = CBMutableCharacteristic(
            type: kCharacteristicUUID,
            properties: .read,
            value: nil, // dynamic via delegate callback
            permissions: .readable
        )

        peripheralDelegate = PeripheralManagerDelegate(plugin: self)
        peripheralManager = CBPeripheralManager(
            delegate: peripheralDelegate,
            queue: DispatchQueue.main
        )

        // The actual advertising starts in peripheralManagerDidUpdateState
        // once Bluetooth is confirmed powered on.
        isAdvertising = true
        invoke.resolve()
    }

    @objc func stopAdvertising(_ invoke: Invoke) {
        peripheralManager?.stopAdvertising()
        peripheralManager?.removeAllServices()
        peripheralManager = nil
        peripheralDelegate = nil
        senderInfoCharacteristic = nil
        senderInfoData = nil
        isAdvertising = false
        invoke.resolve()
    }

    // MARK: - Scanning (Receiver)

    @objc func startScanning(_ invoke: Invoke) {
        guard !isScanning else {
            invoke.reject("Already scanning")
            return
        }

        guard let args = try? invoke.parseArgs(StartScanningArgs.self) else {
            invoke.reject("Invalid arguments")
            return
        }

        targetCodeHash = Data(args.targetCodeHash)

        centralDelegate = CentralManagerDelegate(plugin: self)
        centralManager = CBCentralManager(
            delegate: centralDelegate,
            queue: DispatchQueue.main
        )

        // Actual scanning starts in centralManagerDidUpdateState
        isScanning = true
        invoke.resolve()
    }

    @objc func stopScanning(_ invoke: Invoke) {
        centralManager?.stopScan()
        centralManager = nil
        centralDelegate = nil
        targetCodeHash = nil
        isScanning = false
        invoke.resolve()
    }

    // MARK: - GATT Read (Receiver)

    @objc func readSenderInfo(_ invoke: Invoke) {
        guard let args = try? invoke.parseArgs(ReadSenderInfoArgs.self) else {
            invoke.reject("Invalid arguments")
            return
        }

        // We need a CBCentralManager to connect — reuse or create one
        if centralManager == nil {
            centralDelegate = CentralManagerDelegate(plugin: self)
            centralManager = CBCentralManager(
                delegate: centralDelegate,
                queue: DispatchQueue.main
            )
        }

        pendingReadInvoke = invoke

        // Retrieve the peripheral by identifier
        guard let uuid = UUID(uuidString: args.deviceId) else {
            invoke.reject("Invalid device ID")
            return
        }

        let peripherals = centralManager!.retrievePeripherals(withIdentifiers: [uuid])
        guard let peripheral = peripherals.first else {
            invoke.reject("Device not found: \(args.deviceId)")
            return
        }

        gattDelegate = GattClientDelegate(plugin: self)
        peripheral.delegate = gattDelegate
        connectedPeripheral = peripheral
        centralManager?.connect(peripheral, options: nil)
    }

    // MARK: - Internal helpers

    fileprivate func beginAdvertising() {
        guard let manager = peripheralManager, manager.state == .poweredOn else { return }

        let service = CBMutableService(type: kServiceUUID, primary: true)
        if let characteristic = senderInfoCharacteristic {
            service.characteristics = [characteristic]
        }
        manager.add(service)

        // iOS only allows localName and serviceUUIDs in the advertising data.
        // Service data is not supported — the receiver must connect via GATT to read info.
        manager.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [kServiceUUID],
            CBAdvertisementDataLocalNameKey: "QDrop"
        ])
    }

    fileprivate func beginScanning() {
        guard let manager = centralManager, manager.state == .poweredOn else { return }

        manager.scanForPeripherals(
            withServices: [kServiceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    fileprivate func emitDeviceFound(deviceId: String, codeHash: [UInt8], rssi: Int, matched: Bool) {
        let payload: [String: Any] = [
            "deviceId": deviceId,
            "codeHash": codeHash,
            "rssi": rssi,
            "matched": matched
        ]
        trigger("device-found", data: payload)
    }

    fileprivate func resolveGattRead(json: String) {
        if let invoke = pendingReadInvoke {
            invoke.resolve(["senderInfoJson": json])
            pendingReadInvoke = nil
        }
        if let peripheral = connectedPeripheral {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        connectedPeripheral = nil
        gattDelegate = nil
    }

    fileprivate func rejectGattRead(reason: String) {
        if let invoke = pendingReadInvoke {
            invoke.reject(reason)
            pendingReadInvoke = nil
        }
        if let peripheral = connectedPeripheral {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        connectedPeripheral = nil
        gattDelegate = nil
    }
}

// MARK: - Argument DTOs

private struct StartAdvertisingArgs: Decodable {
    let serviceData: [UInt8]
    let senderInfoJson: String
}

private struct StartScanningArgs: Decodable {
    let targetCodeHash: [UInt8]
}

private struct ReadSenderInfoArgs: Decodable {
    let deviceId: String
}

// MARK: - CBPeripheralManagerDelegate

private class PeripheralManagerDelegate: NSObject, CBPeripheralManagerDelegate {
    weak var plugin: BlePlugin?

    init(plugin: BlePlugin) {
        self.plugin = plugin
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        if peripheral.state == .poweredOn {
            plugin?.beginAdvertising()
        }
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didReceiveRead request: CBATTRequest
    ) {
        guard request.characteristic.uuid == kCharacteristicUUID,
              let data = plugin?.senderInfoData
        else {
            peripheral.respond(to: request, withResult: .attributeNotFound)
            return
        }

        let offset = request.offset
        if offset >= data.count {
            peripheral.respond(to: request, withResult: .invalidOffset)
            return
        }

        request.value = data.subdata(in: offset..<data.count)
        peripheral.respond(to: request, withResult: .success)
    }
}

// MARK: - CBCentralManagerDelegate

private class CentralManagerDelegate: NSObject, CBCentralManagerDelegate {
    weak var plugin: BlePlugin?

    init(plugin: BlePlugin) {
        self.plugin = plugin
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            plugin?.beginScanning()
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let deviceId = peripheral.identifier.uuidString

        // On iOS, service data is not available in advertisement packets.
        // We emit the event with an empty code hash — the receiver should connect
        // via GATT readSenderInfo to verify the sender.
        // matched is always false at scan time on iOS; the front-end handles matching
        // after reading sender info.
        plugin?.emitDeviceFound(
            deviceId: deviceId,
            codeHash: [],
            rssi: RSSI.intValue,
            matched: false
        )
    }

    func centralManager(
        _ central: CBCentralManager,
        didConnect peripheral: CBPeripheral
    ) {
        peripheral.discoverServices([kServiceUUID])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        plugin?.rejectGattRead(reason: "Failed to connect: \(error?.localizedDescription ?? "unknown")")
    }
}

// MARK: - CBPeripheralDelegate (GATT client)

private class GattClientDelegate: NSObject, CBPeripheralDelegate {
    weak var plugin: BlePlugin?

    init(plugin: BlePlugin) {
        self.plugin = plugin
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error = error {
            plugin?.rejectGattRead(reason: "Service discovery failed: \(error.localizedDescription)")
            return
        }
        guard let service = peripheral.services?.first(where: { $0.uuid == kServiceUUID }) else {
            plugin?.rejectGattRead(reason: "BLE service not found on device")
            return
        }
        peripheral.discoverCharacteristics([kCharacteristicUUID], for: service)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        if let error = error {
            plugin?.rejectGattRead(reason: "Characteristic discovery failed: \(error.localizedDescription)")
            return
        }
        guard let characteristic = service.characteristics?.first(where: { $0.uuid == kCharacteristicUUID }) else {
            plugin?.rejectGattRead(reason: "SenderInfo characteristic not found")
            return
        }
        peripheral.readValue(for: characteristic)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        if let error = error {
            plugin?.rejectGattRead(reason: "GATT read failed: \(error.localizedDescription)")
            return
        }
        guard let data = characteristic.value, let json = String(data: data, encoding: .utf8) else {
            plugin?.rejectGattRead(reason: "GATT read returned empty or invalid data")
            return
        }
        plugin?.resolveGattRead(json: json)
    }
}

@_cdecl("init_plugin_ble")
func initPlugin() -> Plugin {
    BlePlugin()
}
