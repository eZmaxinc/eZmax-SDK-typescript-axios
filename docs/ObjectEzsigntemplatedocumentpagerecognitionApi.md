# ObjectEzsigntemplatedocumentpagerecognitionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatedocumentpagerecognitionCreateObjectV1**](#ezsigntemplatedocumentpagerecognitioncreateobjectv1) | **POST** /1/object/ezsigntemplatedocumentpagerecognition | Create a new Ezsigntemplatedocumentpagerecognition|
|[**ezsigntemplatedocumentpagerecognitionDeleteObjectV1**](#ezsigntemplatedocumentpagerecognitiondeleteobjectv1) | **DELETE** /1/object/ezsigntemplatedocumentpagerecognition/{pkiEzsigntemplatedocumentpagerecognitionID} | Delete an existing Ezsigntemplatedocumentpagerecognition|
|[**ezsigntemplatedocumentpagerecognitionEditObjectV1**](#ezsigntemplatedocumentpagerecognitioneditobjectv1) | **PUT** /1/object/ezsigntemplatedocumentpagerecognition/{pkiEzsigntemplatedocumentpagerecognitionID} | Edit an existing Ezsigntemplatedocumentpagerecognition|
|[**ezsigntemplatedocumentpagerecognitionGetObjectV2**](#ezsigntemplatedocumentpagerecognitiongetobjectv2) | **GET** /2/object/ezsigntemplatedocumentpagerecognition/{pkiEzsigntemplatedocumentpagerecognitionID} | Retrieve an existing Ezsigntemplatedocumentpagerecognition|

# **ezsigntemplatedocumentpagerecognitionCreateObjectV1**
> EzsigntemplatedocumentpagerecognitionCreateObjectV1Response ezsigntemplatedocumentpagerecognitionCreateObjectV1(ezsigntemplatedocumentpagerecognitionCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatedocumentpagerecognitionApi,
    Configuration,
    EzsigntemplatedocumentpagerecognitionCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentpagerecognitionApi(configuration);

let ezsigntemplatedocumentpagerecognitionCreateObjectV1Request: EzsigntemplatedocumentpagerecognitionCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentpagerecognitionCreateObjectV1(
    ezsigntemplatedocumentpagerecognitionCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentpagerecognitionCreateObjectV1Request** | **EzsigntemplatedocumentpagerecognitionCreateObjectV1Request**|  | |


### Return type

**EzsigntemplatedocumentpagerecognitionCreateObjectV1Response**

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

# **ezsigntemplatedocumentpagerecognitionDeleteObjectV1**
> EzsigntemplatedocumentpagerecognitionDeleteObjectV1Response ezsigntemplatedocumentpagerecognitionDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentpagerecognitionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentpagerecognitionApi(configuration);

let pkiEzsigntemplatedocumentpagerecognitionID: number; //The unique ID of the Ezsigntemplatedocumentpagerecognition (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatedocumentpagerecognitionDeleteObjectV1(
    pkiEzsigntemplatedocumentpagerecognitionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatedocumentpagerecognitionID** | [**number**] | The unique ID of the Ezsigntemplatedocumentpagerecognition | defaults to undefined|


### Return type

**EzsigntemplatedocumentpagerecognitionDeleteObjectV1Response**

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

# **ezsigntemplatedocumentpagerecognitionEditObjectV1**
> EzsigntemplatedocumentpagerecognitionEditObjectV1Response ezsigntemplatedocumentpagerecognitionEditObjectV1(ezsigntemplatedocumentpagerecognitionEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentpagerecognitionApi,
    Configuration,
    EzsigntemplatedocumentpagerecognitionEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentpagerecognitionApi(configuration);

let pkiEzsigntemplatedocumentpagerecognitionID: number; //The unique ID of the Ezsigntemplatedocumentpagerecognition (default to undefined)
let ezsigntemplatedocumentpagerecognitionEditObjectV1Request: EzsigntemplatedocumentpagerecognitionEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentpagerecognitionEditObjectV1(
    pkiEzsigntemplatedocumentpagerecognitionID,
    ezsigntemplatedocumentpagerecognitionEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentpagerecognitionEditObjectV1Request** | **EzsigntemplatedocumentpagerecognitionEditObjectV1Request**|  | |
| **pkiEzsigntemplatedocumentpagerecognitionID** | [**number**] | The unique ID of the Ezsigntemplatedocumentpagerecognition | defaults to undefined|


### Return type

**EzsigntemplatedocumentpagerecognitionEditObjectV1Response**

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

# **ezsigntemplatedocumentpagerecognitionGetObjectV2**
> EzsigntemplatedocumentpagerecognitionGetObjectV2Response ezsigntemplatedocumentpagerecognitionGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentpagerecognitionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentpagerecognitionApi(configuration);

let pkiEzsigntemplatedocumentpagerecognitionID: number; //The unique ID of the Ezsigntemplatedocumentpagerecognition (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatedocumentpagerecognitionGetObjectV2(
    pkiEzsigntemplatedocumentpagerecognitionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatedocumentpagerecognitionID** | [**number**] | The unique ID of the Ezsigntemplatedocumentpagerecognition | defaults to undefined|


### Return type

**EzsigntemplatedocumentpagerecognitionGetObjectV2Response**

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

