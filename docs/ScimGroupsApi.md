# ScimGroupsApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**groupsCreateObjectScimV2**](#groupscreateobjectscimv2) | **POST** /2/scim/Groups | Create a new Usergroup|
|[**groupsDeleteObjectScimV2**](#groupsdeleteobjectscimv2) | **DELETE** /2/scim/Groups/{groupId} | Delete an existing Usergroup|
|[**groupsEditObjectScimV2**](#groupseditobjectscimv2) | **PUT** /2/scim/Groups/{groupId} | Edit an existing Usergroup|
|[**groupsGetListScimV2**](#groupsgetlistscimv2) | **GET** /2/scim/Groups | Retrieve Usergroup list|
|[**groupsGetObjectScimV2**](#groupsgetobjectscimv2) | **GET** /2/scim/Groups/{groupId} | Retrieve an existing Usergroup|

# **groupsCreateObjectScimV2**
> ScimGroup groupsCreateObjectScimV2(scimGroup)


### Example

```typescript
import {
    ScimGroupsApi,
    Configuration,
    ScimGroup
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimGroupsApi(configuration);

let scimGroup: ScimGroup; //

const { status, data } = await apiInstance.groupsCreateObjectScimV2(
    scimGroup
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **scimGroup** | **ScimGroup**|  | |


### Return type

**ScimGroup**

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

# **groupsDeleteObjectScimV2**
> groupsDeleteObjectScimV2()


### Example

```typescript
import {
    ScimGroupsApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimGroupsApi(configuration);

let groupId: string; // (default to undefined)

const { status, data } = await apiInstance.groupsDeleteObjectScimV2(
    groupId
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **groupId** | [**string**] |  | defaults to undefined|


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

# **groupsEditObjectScimV2**
> ScimGroup groupsEditObjectScimV2(scimGroup)


### Example

```typescript
import {
    ScimGroupsApi,
    Configuration,
    ScimGroup
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimGroupsApi(configuration);

let groupId: string; // (default to undefined)
let scimGroup: ScimGroup; //

const { status, data } = await apiInstance.groupsEditObjectScimV2(
    groupId,
    scimGroup
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **scimGroup** | **ScimGroup**|  | |
| **groupId** | [**string**] |  | defaults to undefined|


### Return type

**ScimGroup**

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

# **groupsGetListScimV2**
> ScimGroup groupsGetListScimV2()


### Example

```typescript
import {
    ScimGroupsApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimGroupsApi(configuration);

let filter: string; //Filter expression for searching groups (optional) (default to undefined)

const { status, data } = await apiInstance.groupsGetListScimV2(
    filter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **filter** | [**string**] | Filter expression for searching groups | (optional) defaults to undefined|


### Return type

**ScimGroup**

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

# **groupsGetObjectScimV2**
> ScimGroup groupsGetObjectScimV2()


### Example

```typescript
import {
    ScimGroupsApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ScimGroupsApi(configuration);

let groupId: string; // (default to undefined)

const { status, data } = await apiInstance.groupsGetObjectScimV2(
    groupId
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **groupId** | [**string**] |  | defaults to undefined|


### Return type

**ScimGroup**

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

