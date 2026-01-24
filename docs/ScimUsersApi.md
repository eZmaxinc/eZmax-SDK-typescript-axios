# ScimUsersApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**usersCreateObjectScimV2**](#userscreateobjectscimv2) | **POST** /2/scim/Users | Create a new User|
|[**usersDeleteObjectScimV2**](#usersdeleteobjectscimv2) | **DELETE** /2/scim/Users/{userId} | Delete an existing User|
|[**usersEditObjectScimV2**](#userseditobjectscimv2) | **PUT** /2/scim/Users/{userId} | Edit an existing User|
|[**usersGetListScimV2**](#usersgetlistscimv2) | **GET** /2/scim/Users | Retrieve User list|
|[**usersGetObjectScimV2**](#usersgetobjectscimv2) | **GET** /2/scim/Users/{userId} | Retrieve an existing User|

# **usersCreateObjectScimV2**
> ScimUser usersCreateObjectScimV2(scimUser)


### Example

```typescript
import {
    ScimUsersApi,
    Configuration,
    ScimUser
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimUsersApi(configuration);

let scimUser: ScimUser; //

const { status, data } = await apiInstance.usersCreateObjectScimV2(
    scimUser
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **scimUser** | **ScimUser**|  | |


### Return type

**ScimUser**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Created |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usersDeleteObjectScimV2**
> usersDeleteObjectScimV2()


### Example

```typescript
import {
    ScimUsersApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimUsersApi(configuration);

let userId: string; // (default to undefined)

const { status, data } = await apiInstance.usersDeleteObjectScimV2(
    userId
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userId** | [**string**] |  | defaults to undefined|


### Return type

void (empty response body)

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**204** | No Content |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usersEditObjectScimV2**
> ScimUser usersEditObjectScimV2(scimUser)


### Example

```typescript
import {
    ScimUsersApi,
    Configuration,
    ScimUser
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimUsersApi(configuration);

let userId: string; // (default to undefined)
let scimUser: ScimUser; //

const { status, data } = await apiInstance.usersEditObjectScimV2(
    userId,
    scimUser
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **scimUser** | **ScimUser**|  | |
| **userId** | [**string**] |  | defaults to undefined|


### Return type

**ScimUser**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | OK |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usersGetListScimV2**
> ScimUserList usersGetListScimV2()


### Example

```typescript
import {
    ScimUsersApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimUsersApi(configuration);

let filter: string; //Filter expression for searching users (optional) (default to undefined)

const { status, data } = await apiInstance.usersGetListScimV2(
    filter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **filter** | [**string**] | Filter expression for searching users | (optional) defaults to undefined|


### Return type

**ScimUserList**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | OK |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usersGetObjectScimV2**
> ScimUser usersGetObjectScimV2()


### Example

```typescript
import {
    ScimUsersApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimUsersApi(configuration);

let userId: string; // (default to undefined)

const { status, data } = await apiInstance.usersGetObjectScimV2(
    userId
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userId** | [**string**] |  | defaults to undefined|


### Return type

**ScimUser**

### Authorization

[Bearer](../README.md#Bearer)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | OK |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

