# ObjectEzsigndiscussionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigndiscussionCreateObjectV1**](#ezsigndiscussioncreateobjectv1) | **POST** /1/object/ezsigndiscussion | Create a new Ezsigndiscussion|
|[**ezsigndiscussionDeleteObjectV1**](#ezsigndiscussiondeleteobjectv1) | **DELETE** /1/object/ezsigndiscussion/{pkiEzsigndiscussionID} | Delete an existing Ezsigndiscussion|
|[**ezsigndiscussionGetObjectV2**](#ezsigndiscussiongetobjectv2) | **GET** /2/object/ezsigndiscussion/{pkiEzsigndiscussionID} | Retrieve an existing Ezsigndiscussion|

# **ezsigndiscussionCreateObjectV1**
> EzsigndiscussionCreateObjectV1Response ezsigndiscussionCreateObjectV1(ezsigndiscussionCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigndiscussionApi,
    Configuration,
    EzsigndiscussionCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndiscussionApi(configuration);

let ezsigndiscussionCreateObjectV1Request: EzsigndiscussionCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigndiscussionCreateObjectV1(
    ezsigndiscussionCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndiscussionCreateObjectV1Request** | **EzsigndiscussionCreateObjectV1Request**|  | |


### Return type

**EzsigndiscussionCreateObjectV1Response**

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

# **ezsigndiscussionDeleteObjectV1**
> EzsigndiscussionDeleteObjectV1Response ezsigndiscussionDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigndiscussionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndiscussionApi(configuration);

let pkiEzsigndiscussionID: number; //The unique ID of the Ezsigndiscussion (default to undefined)

const { status, data } = await apiInstance.ezsigndiscussionDeleteObjectV1(
    pkiEzsigndiscussionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndiscussionID** | [**number**] | The unique ID of the Ezsigndiscussion | defaults to undefined|


### Return type

**EzsigndiscussionDeleteObjectV1Response**

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

# **ezsigndiscussionGetObjectV2**
> EzsigndiscussionGetObjectV2Response ezsigndiscussionGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigndiscussionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndiscussionApi(configuration);

let pkiEzsigndiscussionID: number; //The unique ID of the Ezsigndiscussion (default to undefined)

const { status, data } = await apiInstance.ezsigndiscussionGetObjectV2(
    pkiEzsigndiscussionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndiscussionID** | [**number**] | The unique ID of the Ezsigndiscussion | defaults to undefined|


### Return type

**EzsigndiscussionGetObjectV2Response**

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

