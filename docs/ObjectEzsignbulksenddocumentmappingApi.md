# ObjectEzsignbulksenddocumentmappingApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignbulksenddocumentmappingCreateObjectV1**](#ezsignbulksenddocumentmappingcreateobjectv1) | **POST** /1/object/ezsignbulksenddocumentmapping | Create a new Ezsignbulksenddocumentmapping|
|[**ezsignbulksenddocumentmappingDeleteObjectV1**](#ezsignbulksenddocumentmappingdeleteobjectv1) | **DELETE** /1/object/ezsignbulksenddocumentmapping/{pkiEzsignbulksenddocumentmappingID} | Delete an existing Ezsignbulksenddocumentmapping|
|[**ezsignbulksenddocumentmappingGetObjectV2**](#ezsignbulksenddocumentmappinggetobjectv2) | **GET** /2/object/ezsignbulksenddocumentmapping/{pkiEzsignbulksenddocumentmappingID} | Retrieve an existing Ezsignbulksenddocumentmapping|
|[**ezsignbulksenddocumentmappingGetObjectV3**](#ezsignbulksenddocumentmappinggetobjectv3) | **GET** /3/object/ezsignbulksenddocumentmapping/{pkiEzsignbulksenddocumentmappingID} | Retrieve an existing Ezsignbulksenddocumentmapping|

# **ezsignbulksenddocumentmappingCreateObjectV1**
> EzsignbulksenddocumentmappingCreateObjectV1Response ezsignbulksenddocumentmappingCreateObjectV1(ezsignbulksenddocumentmappingCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignbulksenddocumentmappingApi,
    Configuration,
    EzsignbulksenddocumentmappingCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksenddocumentmappingApi(configuration);

let ezsignbulksenddocumentmappingCreateObjectV1Request: EzsignbulksenddocumentmappingCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsignbulksenddocumentmappingCreateObjectV1(
    ezsignbulksenddocumentmappingCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignbulksenddocumentmappingCreateObjectV1Request** | **EzsignbulksenddocumentmappingCreateObjectV1Request**|  | |


### Return type

**EzsignbulksenddocumentmappingCreateObjectV1Response**

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

# **ezsignbulksenddocumentmappingDeleteObjectV1**
> EzsignbulksenddocumentmappingDeleteObjectV1Response ezsignbulksenddocumentmappingDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignbulksenddocumentmappingApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksenddocumentmappingApi(configuration);

let pkiEzsignbulksenddocumentmappingID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksenddocumentmappingDeleteObjectV1(
    pkiEzsignbulksenddocumentmappingID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksenddocumentmappingID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksenddocumentmappingDeleteObjectV1Response**

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

# **ezsignbulksenddocumentmappingGetObjectV2**
> EzsignbulksenddocumentmappingGetObjectV2Response ezsignbulksenddocumentmappingGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignbulksenddocumentmappingApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksenddocumentmappingApi(configuration);

let pkiEzsignbulksenddocumentmappingID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksenddocumentmappingGetObjectV2(
    pkiEzsignbulksenddocumentmappingID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksenddocumentmappingID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksenddocumentmappingGetObjectV2Response**

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

# **ezsignbulksenddocumentmappingGetObjectV3**
> EzsignbulksenddocumentmappingGetObjectV3Response ezsignbulksenddocumentmappingGetObjectV3()



### Example

```typescript
import {
    ObjectEzsignbulksenddocumentmappingApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksenddocumentmappingApi(configuration);

let pkiEzsignbulksenddocumentmappingID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksenddocumentmappingGetObjectV3(
    pkiEzsignbulksenddocumentmappingID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksenddocumentmappingID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksenddocumentmappingGetObjectV3Response**

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

