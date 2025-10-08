# [WireGuard](https://www.wireguard.com/) for the NT Kernel
### High performance in-kernel WireGuard implementation for Windows

WireGuardNT is an implementation of WireGuard, for the NT Kernel as used in Windows 7, 8, 8.1, 10, and 11, supporting AMD64, x86, ARM64, and ARM processors.

#### Not the droids you're looking for

**If you've come here looking to run [WireGuard on Windows](https://git.zx2c4.com/wireguard-windows/about/), you're in the wrong place. Instead, head on over to the [WireGuard Download Page](https://www.wireguard.com/install/) to download the WireGuard application.** Alternatively, if you've come here looking to embed WireGuard into your Windows program, **you are still in the wrong place**. Instead, head on over to the [embeddable DLL service project](https://git.zx2c4.com/wireguard-windows/about/embeddable-dll-service/README.md), to get everything you need to bake WireGuard into your Windows programs. These projects use WireGuardNT inside.

## Usage

#### Download

WireGuardNT is deployed as a platform-specific `wireguard.dll` file. Install the `wireguard.dll` file side-by-side with your application. Download the dll from [the wireguard-nt download server](https://download.wireguard.com/wireguard-nt/), alongside the header file for your application described below.

#### API

Include the [`wireguard.h` file](https://git.zx2c4.com/wireguard-nt/tree/api/wireguard.h) in your project simply by copying it there and dynamically load the `wireguard.dll` using [`LoadLibraryEx()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) and [`GetProcAddress()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) to resolve each function, using the typedefs provided in the header file. The [`InitializeWireGuardNT` function in the example.c code](https://git.zx2c4.com/wireguard-nt/tree/example/example.c) provides this in a function that you can simply copy and paste.

With the library setup, WireGuardNT can then be used by first creating an adapter, configuring it, and then setting its status to "up". Adapters have names (e.g. "OfficeNet") and types (e.g. "WireGuard").

```C
WIREGUARD_ADAPTER_HANDLE Adapter1 = WireGuardCreateAdapter(L"OfficeNet", L"WireGuard", &SomeFixedGUID1);
WIREGUARD_ADAPTER_HANDLE Adapter2 = WireGuardCreateAdapter(L"HomeNet", L"WireGuard", &SomeFixedGUID2);
WIREGUARD_ADAPTER_HANDLE Adapter3 = WireGuardCreateAdapter(L"Data Center", L"WireGuard", &SomeFixedGUID3);
```

After creating an adapter, we can use it by setting a configuration and setting its status to "up":

```C
struct
{
    WIREGUARD_INTERFACE Interface;
    WIREGUARD_PEER FirstPeer;
    WIREGUARD_ALLOWED_IP FirstPeerAllowedIP1;
    WIREGUARD_ALLOWED_IP FirstPeerAllowedIP2;
    WIREGUARD_PEER SecondPeer;
    WIREGUARD_ALLOWED_IP SecondtPeerAllowedIP1;
} Config = {
    .Interface = {
        .Flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY,
        .PrivateKey = ...,
        .PeersCount = 2
    },
    .FirstPeer = {
        .Flags = WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_HAS_ENDPOINT,
        .PublicKey = ...,
        .Endpoint = ...,
        .AllowedIPsCount = 2
    },
    .FirstPeerAllowedIP1 = { ... },
    ...
};
WireGuardSetConfiguration(Adapter1, &Config.Interface, sizeof(Config));
WireGuardSetAdapterState(Adapter1, WIREGUARD_ADAPTER_STATE_UP);
```

You are *highly encouraged* to read the [**example.c short example**](https://git.zx2c4.com/wireguard-nt/tree/example/example.c) to see how to put together a simple network tunnel. The example one connects to the [demo server](https://demo.wireguard.com/).

The various functions and definitions are [documented in `wireguard.h`](https://git.zx2c4.com/wireguard-nt/tree/api/wireguard.h) as well as in the reference below.

## API Reference

### Type:  `WIREGUARD_ADAPTER_HANDLE` - opaque type to an instance of a WireGuard adapter.

### Function: `WireGuardCreateAdapter` - creates a new adapter.

```c
WIREGUARD_ADAPTER_HANDLE WireGuardCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID);
```

Typedef'd as `WIREGUARD_CREATE_ADAPTER_FUNC`. Returns a `WIREGUARD_ADAPTER_HANDLE` if successful, which must be released with `WireGuardCloseAdapter`; otherwise returns `NULL` and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`LPCWSTR`|Name|The requested name of the adapter. Zero-terminated string of up to `MAX_ADAPTER_NAME-1` characters.|
|`LPCWSTR`|TunnelType|Name of the adapter tunnel type. Zero-terminated string of up to `MAX_ADAPTER_NAME-1` characters.|
|`GUID *`|RequestedGUID|The GUID of the created network adapter, which then influences NLA generation deterministically. If it is set to `NULL`, the GUID is chosen by the system at random, and hence a new NLA entry is created for each new adapter.|

### Function: `WireGuardOpenAdapter` - opens an existing adapter.

```c
WIREGUARD_ADAPTER_HANDLE WireGuardOpenAdapter(LPCWSTR Name);
```

Typedef'd as `WIREGUARD_OPEN_ADAPTER_FUNC`. Returns a `WIREGUARD_ADAPTER_HANDLE` if successful, which must be released with `WireGuardCloseAdapter`; otherwise returns `NULL` and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`LPCWSTR`|Name|The requested name of the adapter. Zero-terminated string of up to `MAX_ADAPTER_NAME-1` characters.|

### Function: `WireGuardCloseAdapter` - closes an open adapter and releases its resources.

```c
VOID WireGuardCloseAdapter(WIREGUARD_ADAPTER_HANDLE Adapter);
```

Typedef'd as `WIREGUARD_CLOSE_ADAPTER_FUNC`. Releases WireGuard adapter resources and, if adapter was created with `WireGuardCreateAdapter`, removes adapter.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `WireGuardCreateAdapter` or `WireGuardOpenAdapter`.|

### Function: `WireGuardGetAdapterLUID` - gets the LUID of an adapter.

```c
VOID WireGuardGetAdapterLUID(WIREGUARD_ADAPTER_HANDLE Adapter, NET_LUID *Luid);
```

Typedef'd as `WIREGUARD_GET_ADAPTER_LUID_FUNC`. Returns the LUID of the adapter into the variable passed as the `Luid` argument.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `WireGuardCreateAdapter` or `WireGuardOpenAdapter`.|
|`NET_LUID *` (out)|Luid|Pointer to receive adapter LUID.|

### Function: `WireGuardGetRunningDriverVersion` - gets the version of the loaded driver.

```c
DWORD WireGuardGetRunningDriverVersion(VOID);
```

Typedef'd as `WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC`. Returns the version of the WireGuardNT driver currently loaded, or zero on error and sets LastError, which is `ERROR_FILE_NOT_FOUND` if WireGuardNT is not currently loaded.

### Function: `WireGuardDeleteDriver` - deletes driver if not in use.

```c
BOOL WireGuardDeleteDriver(VOID);
```

Typedef'd as `WIREGUARD_DELETE_DRIVER_FUNC`. Deletes the WireGuardNT driver if there are no more adapters in use, and returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

### Enumeration: `WIREGUARD_LOGGER_LEVEL` - determines level of logging.

|Name|Description|
|--|--|
|`WIREGUARD_LOG_INFO`|Informational|
|`WIREGUARD_LOG_WARN`|Warning|
|`WIREGUARD_LOG_ERR`|Error|

### Callback type: `WIREGUARD_LOGGER_CALLBACK` - called for each log message.

```c
VOID WireGuardLoggerCallback(WIREGUARD_LOGGER_LEVEL Level, DWORD64 Timestamp, LPCWSTR Message);
```

Typedef'd as `WIREGUARD_LOGGER_CALLBACK`. Called by the library on each log message.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_LOGGER_LEVEL`|Level|Message level.|
|`DWORD64`|Timestamp|Message timestamp in in 100ns intervals since 1601-01-01 UTC.|
|`LPCWSTR`|Message|Message text.|

### Function: `WireGuardSetLogger` - registers logger callback function.

```c
VOID WireGuardSetLogger(WIREGUARD_LOGGER_CALLBACK NewLogger);
```

Typedef'd as `WIREGUAR_SET_LOGGER_FUNC`. After registration, the callback may be called concurrently by multiple threads. It is up to the supplied callback function, `NewLogger`, to handle synchronization. If `NewLogger` is `NULL`, logging is disabled.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_LOGGER_CALLBACK`|NewLogger|Pointer to callback function to use as a new global logger.|

### Enumeration: `WIREGUARD_ADAPTER_LOG_STATE` - determines adapter log generation.

|Name|Description|
|--|--|
|`WIREGUARD_ADAPTER_LOG_OFF`|No logs are generated from the driver.|
|`WIREGUARD_ADAPTER_LOG_ON`|Logs are generated from the driver.|
|`WIREGUARD_ADAPTER_LOG_ON_WITH_PREFIX`|Logs are generated from the driver, adapter index-prefixed.|

### Function: `WireGuardSetAdapterLogging` - sets whether adapter logs are generated.

```c
BOOL WireGuardSetAdapterLogging(WIREGUARD_ADAPTER_HANDLE Adapter, WIREGUARD_ADAPTER_LOG_STATE LogState);
```

Typedef'd as `WIREGUARD_SET_ADAPTER_LOGGING`.  Sets whether and how the specified adapter logs to the logger previously set by `WireGuardSetLogger`.  Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `WireGuardCreateAdapter` or `WireGuardOpenAdapter`.|
|`WIREGUARD_ADAPTER_LOG_STATE`|LogState|Adapter logging state.|

### Enumeration: `WIREGUARD_ADAPTER_STATE` - determines adapter state.

|Name|Description|
|--|--|
|`WIREGUARD_ADAPTER_STATE_DOWN`|Down|
|`WIREGUARD_ADAPTER_STATE_UP`|Up|

### Function: `WireGuardSetAdapterState` - sets state of adapter.

```c
BOOL WireGuardSetAdapterState(WIREGUARD_ADAPTER_HANDLE Adapter, WIREGUARD_ADAPTER_STATE State);
```

Typedef'd as `WIREGUARD_SET_ADAPTER_STATE`.  Sets the specified adapter up or down. Note that sockets used by the specified adapter are owned by the process that sets the adapter up. Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `WireGuardCreateAdapter` or `WireGuardOpenAdapter`.|
|`WIREGUARD_ADAPTER_STATE`|State|Adapter state.|

### Function: `WireGuardGetAdapterState` - gets state of adapter.

```c
BOOL WireGuardGetAdapterState(WIREGUARD_ADAPTER_HANDLE Adapter, WIREGUARD_ADAPTER_STATE *State);
```

Typedef'd as `WIREGUARD_GET_ADAPTER_STATE`.  Gets whether the specified adapter is up or down. Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `WireGuardCreateAdapter` or `WireGuardOpenAdapter`.|
|`WIREGUARD_ADAPTER_STATE` (out)|State|Pointer to adapter state.|

### Structure: `WIREGUARD_INTERFACE` - an interface.

|Type|Name|Description|
|--|--|--|
|`WIREGUARD_INTERFACE_FLAG`|Flags|Bitwise combination of flags.|
|`WORD`|ListenPort|Port for UDP listen socket, or 0 to choose randomly.|
|`BYTE[WIREGUARD_KEY_LENGTH]`|PrivateKey|Private key of interface.| 
|`BYTE[WIREGUARD_KEY_LENGTH]`|PublicKey|Corresponding public key of private key (unused on set).|
|`DWORD`|PeersCount|Number of peer structures following this structure.|

### Structure: `WIREGUARD_PEER` - a peer.

|Type|Name|Description|
|--|--|--|
|`WIREGUARD_PEER_FLAG`|Flags|Bitwise combination of flags.|
|`DWORD`|Reserved|Reserved; must be zero.|
|`BYTE[WIREGUARD_KEY_LENGTH]`|PublicKey|Public key, the peer's primary identifier.|
|`BYTE[WIREGUARD_KEY_LENGTH]`|PresharedKey|Preshared key for additional layer of post-quantum resistance.|
|`WORD`|PersistentKeepalive|Persistent keep-alive seconds interval, or 0 to disable.|
|`SOCKADDR_INET`|Endpoint|Endpoint, with IP address and UDP port number.|
|`DWORD64`|TxBytes|Number of bytes transmitted (unused on set).|
|`DWORD64`|RxBytes|Number of bytes received (unused on set).|
|`DWORD64`|LastHandshake|Time of the last handshake, in 100ns intervals since 1601-01-01 UTC (unused on set).|
|`DWORD`|AllowedIPsCount|Number of allowed IP structures following this structure.|

### Structure: `WIREGUARD_ALLOWED_IP` - an IP network range.

|Type|Name|Description|
|--|--|--|
|Union|Address|IP address; the `V4` member is a `IN_ADDR` and the `V6` member is a `IN6_ADDR`.|
|`ADDRESS_FAMILY`|AddressFamily|Address family, either `AF_INET` or `AF_INET6`.|
|`BYTE`|Cidr|The CIDR of the address range.|

### Constant: `WIREGUARD_KEY_LENGTH` - the length of a key.

All WireGuard keys -- public, private, or pre-shared -- are 32 bytes in length.

### Enumeration: `WIREGUARD_INTERFACE_FLAG` - bitwise flags for interfaces.

These values may be or'd together.

|Name|Description|
|--|--|
|`WIREGUARD_INTERFACE_HAS_PUBLIC_KEY`|The PublicKey field is set (unused on set).|
|`WIREGUARD_INTERFACE_HAS_PRIVATE_KEY`|The PrivateKey field is set.|
|`WIREGUARD_INTERFACE_HAS_LISTEN_PORT`|The ListenPort field is set.|
|`WIREGUARD_INTERFACE_REPLACE_PEERS`|Remove all peers before adding new ones (unused on get).|

### Enumeration: `WIREGUARD_PEER_FLAG` - bitwise flags for peers.

These values may be or'd together.

|Name|Description|
|--|--|
|`WIREGUARD_PEER_HAS_PUBLIC_KEY`|The PublicKey field is set.|
|`WIREGUARD_PEER_HAS_PRESHARED_KEY`|The PresharedKey field is set.|
|`WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE`|The PersistentKeepAlive field is set.|
|`WIREGUARD_PEER_HAS_ENDPOINT`|The Endpoint field is set.|
|`WIREGUARD_PEER_REPLACE_ALLOWED_IPS`|Remove all allowed IPs before adding new ones (unused on get).|
|`WIREGUARD_PEER_REMOVE`|Remove specified peer (unused on get).|
|`WIREGUARD_PEER_UPDATE`|Do not add a new peer (unused on get).|

### Function: `WireGuardSetConfiguration` - sets configuration of adapter.

```c
BOOL WireGuardSetConfiguration(WIREGUARD_ADAPTER_HANDLE Adapter, const WIREGUARD_INTERFACE *Config, DWORD Bytes);
```

Typedef'd as `WIREGUARD_SET_CONFIGURATION`.  Sets the configuration of the specified adapter. The `Config` argument represents a `WIREGUARD_INTERFACE` structure, immediately followed in memory by zero or more `WIREGUARD_PEER` or `WIREGUARD_ALLOWED_IP` structures. Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `WireGuardCreateAdapter` or `WireGuardOpenAdapter`.|
|`WIREGUARD_INTERFACE *`|Config|Adapter configuration.|
|`DWORD`|Bytes|Number of bytes of `Config` allocation.|


### Function: `WireGuardGetConfiguration` - gets configuration of adapter.

```c
BOOL WireGuardGetConfiguration(WIREGUARD_ADAPTER_HANDLE Adapter, WIREGUARD_INTERFACE *Config, DWORD *Bytes);
```

Typedef'd as `WIREGUARD_GET_CONFIGURATION`.  Gets the configuration of the specified adapter. The `Config` argument represents a `WIREGUARD_INTERFACE` structure, immediately followed in memory by zero or more `WIREGUARD_PEER` or `WIREGUARD_ALLOWED_IP` structures. Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError. If LastError is `ERROR_MORE_DATA`, `Bytes` is updated with the number of bytes needed for successful operation. Since that byte value can change, this function should be called in a tight loop until success or until the error is not `ERROR_MORE_DATA`.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`WIREGUARD_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `WireGuardCreateAdapter` or `WireGuardOpenAdapter`.|
|`WIREGUARD_INTERFACE *` (out)|Config|Adapter configuration.|
|`DWORD *` (in/out)|Bytes|Pointer to number of bytes of `Config` allocation, on input, and is updated when the function returns to the amount of bytes required.|

## Building

**Do not distribute drivers or files named "WireGuard" or "wireguard" or similar, as they will most certainly clash with official deployments. Instead distribute [`wireguard.dll` as downloaded from the wireguard-nt download server](https://download.wireguard.com/wireguard-nt/).**

General requirements:

- [Visual Studio 2019](https://visualstudio.microsoft.com/downloads/) with Windows SDK
- [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

`wireguard-nt.sln` may be opened in Visual Studio for development and building. Be sure to run `bcdedit /set testsigning on` and then reboot before to enable unsigned driver loading. The default run sequence (F5) in Visual Studio will build the example project and its dependencies.

## License

The entire contents of [this repository](https://git.zx2c4.com/wireguard-nt/), including all documentation and example code, is "Copyright © 2018-2021 WireGuard LLC. All Rights Reserved." Source code is licensed under the [GPLv2](COPYING). Prebuilt binaries from [the wireguard-nt download server](https://download.wireguard.com/wireguard-nt/) are released under a more permissive license suitable for more forms of software contained inside of the .zip files distributed there.
