# ObjectEzsignbulksendsignermappingApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignbulksendsignermappingCreateObjectV1**](#ezsignbulksendsignermappingcreateobjectv1) | **POST** /1/object/ezsignbulksendsignermapping | Create a new Ezsignbulksendsignermapping|
|[**ezsignbulksendsignermappingDeleteObjectV1**](#ezsignbulksendsignermappingdeleteobjectv1) | **DELETE** /1/object/ezsignbulksendsignermapping/{pkiEzsignbulksendsignermappingID} | Delete an existing Ezsignbulksendsignermapping|
|[**ezsignbulksendsignermappingGetObjectV2**](#ezsignbulksendsignermappinggetobjectv2) | **GET** /2/object/ezsignbulksendsignermapping/{pkiEzsignbulksendsignermappingID} | Retrieve an existing Ezsignbulksendsignermapping|

# **ezsignbulksendsignermappingCreateObjectV1**
> EzsignbulksendsignermappingCreateObjectV1Response ezsignbulksendsignermappingCreateObjectV1(ezsignbulksendsignermappingCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignbulksendsignermappingApi,
    Configuration,
    EzsignbulksendsignermappingCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendsignermappingApi(configuration);

let ezsignbulksendsignermappingCreateObjectV1Request: EzsignbulksendsignermappingCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsignbulksendsignermappingCreateObjectV1(
    ezsignbulksendsignermappingCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignbulksendsignermappingCreateObjectV1Request** | **EzsignbulksendsignermappingCreateObjectV1Request**|  | |


### Return type

**EzsignbulksendsignermappingCreateObjectV1Response**

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

# **ezsignbulksendsignermappingDeleteObjectV1**
> EzsignbulksendsignermappingDeleteObjectV1Response ezsignbulksendsignermappingDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignbulksendsignermappingApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendsignermappingApi(configuration);

let pkiEzsignbulksendsignermappingID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendsignermappingDeleteObjectV1(
    pkiEzsignbulksendsignermappingID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendsignermappingID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendsignermappingDeleteObjectV1Response**

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

# **ezsignbulksendsignermappingGetObjectV2**
> EzsignbulksendsignermappingGetObjectV2Response ezsignbulksendsignermappingGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignbulksendsignermappingApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendsignermappingApi(configuration);

let pkiEzsignbulksendsignermappingID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendsignermappingGetObjectV2(
    pkiEzsignbulksendsignermappingID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendsignermappingID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendsignermappingGetObjectV2Response**

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

