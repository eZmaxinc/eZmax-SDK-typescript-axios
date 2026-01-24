# ObjectUsergroupdelegationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**usergroupdelegationCreateObjectV1**](#usergroupdelegationcreateobjectv1) | **POST** /1/object/usergroupdelegation | Create a new Usergroupdelegation|
|[**usergroupdelegationDeleteObjectV1**](#usergroupdelegationdeleteobjectv1) | **DELETE** /1/object/usergroupdelegation/{pkiUsergroupdelegationID} | Delete an existing Usergroupdelegation|
|[**usergroupdelegationEditObjectV1**](#usergroupdelegationeditobjectv1) | **PUT** /1/object/usergroupdelegation/{pkiUsergroupdelegationID} | Edit an existing Usergroupdelegation|
|[**usergroupdelegationGetObjectV2**](#usergroupdelegationgetobjectv2) | **GET** /2/object/usergroupdelegation/{pkiUsergroupdelegationID} | Retrieve an existing Usergroupdelegation|

# **usergroupdelegationCreateObjectV1**
> UsergroupdelegationCreateObjectV1Response usergroupdelegationCreateObjectV1(usergroupdelegationCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectUsergroupdelegationApi,
    Configuration,
    UsergroupdelegationCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupdelegationApi(configuration);

let usergroupdelegationCreateObjectV1Request: UsergroupdelegationCreateObjectV1Request; //

const { status, data } = await apiInstance.usergroupdelegationCreateObjectV1(
    usergroupdelegationCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupdelegationCreateObjectV1Request** | **UsergroupdelegationCreateObjectV1Request**|  | |


### Return type

**UsergroupdelegationCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usergroupdelegationDeleteObjectV1**
> UsergroupdelegationDeleteObjectV1Response usergroupdelegationDeleteObjectV1()



### Example

```typescript
import {
    ObjectUsergroupdelegationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupdelegationApi(configuration);

let pkiUsergroupdelegationID: number; //The unique ID of the Usergroupdelegation (default to undefined)

const { status, data } = await apiInstance.usergroupdelegationDeleteObjectV1(
    pkiUsergroupdelegationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupdelegationID** | [**number**] | The unique ID of the Usergroupdelegation | defaults to undefined|


### Return type

**UsergroupdelegationDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usergroupdelegationEditObjectV1**
> UsergroupdelegationEditObjectV1Response usergroupdelegationEditObjectV1(usergroupdelegationEditObjectV1Request)



### Example

```typescript
import {
    ObjectUsergroupdelegationApi,
    Configuration,
    UsergroupdelegationEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupdelegationApi(configuration);

let pkiUsergroupdelegationID: number; //The unique ID of the Usergroupdelegation (default to undefined)
let usergroupdelegationEditObjectV1Request: UsergroupdelegationEditObjectV1Request; //

const { status, data } = await apiInstance.usergroupdelegationEditObjectV1(
    pkiUsergroupdelegationID,
    usergroupdelegationEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupdelegationEditObjectV1Request** | **UsergroupdelegationEditObjectV1Request**|  | |
| **pkiUsergroupdelegationID** | [**number**] | The unique ID of the Usergroupdelegation | defaults to undefined|


### Return type

**UsergroupdelegationEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usergroupdelegationGetObjectV2**
> UsergroupdelegationGetObjectV2Response usergroupdelegationGetObjectV2()



### Example

```typescript
import {
    ObjectUsergroupdelegationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupdelegationApi(configuration);

let pkiUsergroupdelegationID: number; //The unique ID of the Usergroupdelegation (default to undefined)

const { status, data } = await apiInstance.usergroupdelegationGetObjectV2(
    pkiUsergroupdelegationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupdelegationID** | [**number**] | The unique ID of the Usergroupdelegation | defaults to undefined|


### Return type

**UsergroupdelegationGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

