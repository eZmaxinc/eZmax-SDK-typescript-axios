# ObjectPermissionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**permissionCreateObjectV1**](#permissioncreateobjectv1) | **POST** /1/object/permission | Create a new Permission|
|[**permissionDeleteObjectV1**](#permissiondeleteobjectv1) | **DELETE** /1/object/permission/{pkiPermissionID} | Delete an existing Permission|
|[**permissionEditObjectV1**](#permissioneditobjectv1) | **PUT** /1/object/permission/{pkiPermissionID} | Edit an existing Permission|
|[**permissionGetObjectV2**](#permissiongetobjectv2) | **GET** /2/object/permission/{pkiPermissionID} | Retrieve an existing Permission|

# **permissionCreateObjectV1**
> PermissionCreateObjectV1Response permissionCreateObjectV1(permissionCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectPermissionApi,
    Configuration,
    PermissionCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPermissionApi(configuration);

let permissionCreateObjectV1Request: PermissionCreateObjectV1Request; //

const { status, data } = await apiInstance.permissionCreateObjectV1(
    permissionCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **permissionCreateObjectV1Request** | **PermissionCreateObjectV1Request**|  | |


### Return type

**PermissionCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **permissionDeleteObjectV1**
> PermissionDeleteObjectV1Response permissionDeleteObjectV1()



### Example

```typescript
import {
    ObjectPermissionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPermissionApi(configuration);

let pkiPermissionID: number; //The unique ID of the Permission (default to undefined)

const { status, data } = await apiInstance.permissionDeleteObjectV1(
    pkiPermissionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPermissionID** | [**number**] | The unique ID of the Permission | defaults to undefined|


### Return type

**PermissionDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **permissionEditObjectV1**
> PermissionEditObjectV1Response permissionEditObjectV1(permissionEditObjectV1Request)



### Example

```typescript
import {
    ObjectPermissionApi,
    Configuration,
    PermissionEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPermissionApi(configuration);

let pkiPermissionID: number; //The unique ID of the Permission (default to undefined)
let permissionEditObjectV1Request: PermissionEditObjectV1Request; //

const { status, data } = await apiInstance.permissionEditObjectV1(
    pkiPermissionID,
    permissionEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **permissionEditObjectV1Request** | **PermissionEditObjectV1Request**|  | |
| **pkiPermissionID** | [**number**] | The unique ID of the Permission | defaults to undefined|


### Return type

**PermissionEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **permissionGetObjectV2**
> PermissionGetObjectV2Response permissionGetObjectV2()



### Example

```typescript
import {
    ObjectPermissionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPermissionApi(configuration);

let pkiPermissionID: number; //The unique ID of the Permission (default to undefined)

const { status, data } = await apiInstance.permissionGetObjectV2(
    pkiPermissionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPermissionID** | [**number**] | The unique ID of the Permission | defaults to undefined|


### Return type

**PermissionGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

