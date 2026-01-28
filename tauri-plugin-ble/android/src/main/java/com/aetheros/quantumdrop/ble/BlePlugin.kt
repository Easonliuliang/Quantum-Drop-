package com.aetheros.quantumdrop.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONArray
import java.util.UUID

private const val TAG = "BlePlugin"
private val SERVICE_UUID: UUID = UUID.fromString("7D2EA8B0-F94C-4B6D-9C8F-3A1B5E6D0F2A")
private val CHARACTERISTIC_UUID: UUID = UUID.fromString("7D2EA8B1-F94C-4B6D-9C8F-3A1B5E6D0F2A")
private val SERVICE_PARCEL_UUID = ParcelUuid(SERVICE_UUID)

// MARK: - InvokeArg DTOs

@InvokeArg
class StartAdvertisingArgs {
    lateinit var serviceData: IntArray
    lateinit var senderInfoJson: String
}

@InvokeArg
class StartScanningArgs {
    lateinit var targetCodeHash: IntArray
}

@InvokeArg
class ReadSenderInfoArgs {
    lateinit var deviceId: String
}

// MARK: - Plugin

@TauriPlugin
class BlePlugin(private val activity: android.app.Activity) : Plugin(activity) {

    private var bluetoothAdapter: BluetoothAdapter? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var gattServer: BluetoothGattServer? = null
    private var scanner: BluetoothLeScanner? = null

    private var isAdvertising = false
    private var isScanning = false

    private var senderInfoBytes: ByteArray? = null
    private var serviceDataBytes: ByteArray? = null
    private var targetCodeHash: ByteArray? = null

    // GATT read state
    private var pendingReadInvoke: Invoke? = null
    private var connectedGatt: BluetoothGatt? = null

    private fun ensureAdapter(): BluetoothAdapter? {
        if (bluetoothAdapter == null) {
            val manager = activity.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            bluetoothAdapter = manager?.adapter
        }
        return bluetoothAdapter
    }

    // MARK: - Advertising

    @SuppressLint("MissingPermission")
    @Command
    fun startAdvertising(invoke: Invoke) {
        if (isAdvertising) {
            invoke.reject("Already advertising")
            return
        }

        val args = invoke.parseArgs(StartAdvertisingArgs::class.java)
        senderInfoBytes = args.senderInfoJson.toByteArray(Charsets.UTF_8)
        serviceDataBytes = args.serviceData.map { it.toByte() }.toByteArray()

        val adapter = ensureAdapter()
        if (adapter == null || !adapter.isEnabled) {
            invoke.reject("Bluetooth is unavailable or disabled")
            return
        }

        advertiser = adapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            invoke.reject("BLE advertising is not supported on this device")
            return
        }

        // Start GATT server first so characteristics are ready before advertising
        startGattServer()

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        val dataBuilder = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(SERVICE_PARCEL_UUID)

        // Add service data (up to ~10 bytes of code hash prefix)
        if (serviceDataBytes != null && serviceDataBytes!!.isNotEmpty()) {
            dataBuilder.addServiceData(SERVICE_PARCEL_UUID, serviceDataBytes)
        }

        advertiser?.startAdvertising(settings, dataBuilder.build(), advertiseCallback)
        isAdvertising = true
        invoke.resolve()
    }

    @SuppressLint("MissingPermission")
    @Command
    fun stopAdvertising(invoke: Invoke) {
        advertiser?.stopAdvertising(advertiseCallback)
        gattServer?.close()
        gattServer = null
        advertiser = null
        senderInfoBytes = null
        serviceDataBytes = null
        isAdvertising = false
        invoke.resolve()
    }

    @SuppressLint("MissingPermission")
    private fun startGattServer() {
        val manager = activity.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            ?: return

        gattServer = manager.openGattServer(activity, gattServerCallback)

        val characteristic = BluetoothGattCharacteristic(
            CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )

        val service = BluetoothGattService(
            SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )
        service.addCharacteristic(characteristic)
        gattServer?.addService(service)
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d(TAG, "BLE advertising started")
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "BLE advertising failed: errorCode=$errorCode")
            isAdvertising = false
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @SuppressLint("MissingPermission")
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            if (characteristic.uuid == CHARACTERISTIC_UUID) {
                val data = senderInfoBytes ?: ByteArray(0)
                val responseData = if (offset < data.size) {
                    data.copyOfRange(offset, data.size)
                } else {
                    ByteArray(0)
                }
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    offset,
                    responseData
                )
            } else {
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED,
                    0,
                    null
                )
            }
        }
    }

    // MARK: - Scanning

    @SuppressLint("MissingPermission")
    @Command
    fun startScanning(invoke: Invoke) {
        if (isScanning) {
            invoke.reject("Already scanning")
            return
        }

        val args = invoke.parseArgs(StartScanningArgs::class.java)
        targetCodeHash = args.targetCodeHash.map { it.toByte() }.toByteArray()

        val adapter = ensureAdapter()
        if (adapter == null || !adapter.isEnabled) {
            invoke.reject("Bluetooth is unavailable or disabled")
            return
        }

        scanner = adapter.bluetoothLeScanner
        if (scanner == null) {
            invoke.reject("BLE scanning is not supported on this device")
            return
        }

        val filter = ScanFilter.Builder()
            .setServiceUuid(SERVICE_PARCEL_UUID)
            .build()

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        scanner?.startScan(listOf(filter), settings, scanCallback)
        isScanning = true
        invoke.resolve()
    }

    @SuppressLint("MissingPermission")
    @Command
    fun stopScanning(invoke: Invoke) {
        scanner?.stopScan(scanCallback)
        scanner = null
        targetCodeHash = null
        isScanning = false
        invoke.resolve()
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val deviceId = result.device.address
            val rssi = result.rssi

            // Extract service data (Android supports this in advertisement)
            val serviceData = result.scanRecord?.getServiceData(SERVICE_PARCEL_UUID)
            val codeHash = serviceData ?: ByteArray(0)

            // Compare code hash if we have target
            val matched = if (targetCodeHash != null && codeHash.isNotEmpty()) {
                codeHash.contentEquals(targetCodeHash)
            } else {
                false
            }

            val payload = JSObject()
            payload.put("deviceId", deviceId)
            val hashArray = JSONArray()
            codeHash.forEach { hashArray.put(it.toInt() and 0xFF) }
            payload.put("codeHash", hashArray)
            payload.put("rssi", rssi)
            payload.put("matched", matched)

            trigger("device-found", payload)
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "BLE scan failed: errorCode=$errorCode")
            isScanning = false
        }
    }

    // MARK: - GATT Read

    @SuppressLint("MissingPermission")
    @Command
    fun readSenderInfo(invoke: Invoke) {
        val args = invoke.parseArgs(ReadSenderInfoArgs::class.java)
        val adapter = ensureAdapter()
        if (adapter == null || !adapter.isEnabled) {
            invoke.reject("Bluetooth is unavailable or disabled")
            return
        }

        val device: BluetoothDevice = adapter.getRemoteDevice(args.deviceId)
        pendingReadInvoke = invoke

        connectedGatt = device.connectGatt(activity, false, gattClientCallback)
    }

    private val gattClientCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                if (pendingReadInvoke != null) {
                    pendingReadInvoke?.reject("Disconnected before read completed")
                    pendingReadInvoke = null
                }
                gatt.close()
                connectedGatt = null
            }
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                pendingReadInvoke?.reject("Service discovery failed: status=$status")
                pendingReadInvoke = null
                gatt.disconnect()
                return
            }

            val service = gatt.getService(SERVICE_UUID)
            if (service == null) {
                pendingReadInvoke?.reject("BLE service not found on device")
                pendingReadInvoke = null
                gatt.disconnect()
                return
            }

            val characteristic = service.getCharacteristic(CHARACTERISTIC_UUID)
            if (characteristic == null) {
                pendingReadInvoke?.reject("SenderInfo characteristic not found")
                pendingReadInvoke = null
                gatt.disconnect()
                return
            }

            gatt.readCharacteristic(characteristic)
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                pendingReadInvoke?.reject("GATT read failed: status=$status")
                pendingReadInvoke = null
                gatt.disconnect()
                return
            }

            val data = characteristic.value
            if (data == null || data.isEmpty()) {
                pendingReadInvoke?.reject("GATT read returned empty data")
                pendingReadInvoke = null
                gatt.disconnect()
                return
            }

            val json = String(data, Charsets.UTF_8)
            val result = JSObject()
            result.put("senderInfoJson", json)
            pendingReadInvoke?.resolve(result)
            pendingReadInvoke = null
            gatt.disconnect()
        }
    }
}
